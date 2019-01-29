import inspect
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

_backend = default_backend()


class _args_mixin:
    def keys(self):
        return list(inspect.signature(type(self)).parameters)
    def __getitem__(self, key):
        return getattr(self, key)


class _cipher_adapter:

    def __init__(self):
        self.key_bytes, self.nonce_bytes = self.key_bits // 8, self.nonce_bits // 8

    def encrypt(self, data, key):
        cipher = self.cipher(key)
        nonce = os.urandom(self.nonce_bytes)
        return nonce + cipher.encrypt(nonce, data, None)

    def decrypt(self, data, key):
        cipher = self.cipher(key)
        nonce, ciphertext = data[:self.nonce_bytes], data[self.nonce_bytes:]
        return cipher.decrypt(nonce, ciphertext, None)


class aes_gcm(_args_mixin, _cipher_adapter):
    cipher = aead.AESGCM
    def __init__(self, *, key_bits=256, nonce_bits=128):
        self.key_bits, self.nonce_bits = key_bits, nonce_bits
        super().__init__()


class chacha20_poly1305(_args_mixin, _cipher_adapter):
    cipher = aead.ChaCha20Poly1305
    key_bits = 256
    nonce_bits = 96


class scrypt(_args_mixin, Scrypt):
    def __init__(self, *, length, n=1 << 22, r=8, p=1, salt=None):
        if salt is None:
            # Make it the same length as the key
            salt = os.urandom(length)
        self.length, self.n, self.r, self.p, self.salt = length, n, r, p, salt
        super().__init__(n=n, r=r, p=p, salt=salt, length=length, backend=_backend)
