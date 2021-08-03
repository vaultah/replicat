import hashlib
import os

import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import _replicat_adapters
from .. import exceptions

_backend = default_backend()


class _aead_cipher_adapter:
    def __init__(self):
        self.key_bytes, self.nonce_bytes = self.key_bits // 8, self.nonce_bits // 8

    def encrypt(self, data, key):
        cipher = self.cipher(key)
        nonce = os.urandom(self.nonce_bytes)
        return nonce + cipher.encrypt(nonce, data, None)

    def decrypt(self, data, key):
        cipher = self.cipher(key)
        nonce, ciphertext = data[: self.nonce_bytes], data[self.nonce_bytes :]
        try:
            return cipher.decrypt(nonce, ciphertext, None)
        except cryptography.exceptions.InvalidTag as e:
            raise exceptions.ReplicatError('Decryption failed') from e


class aes_gcm(_aead_cipher_adapter):
    cipher = aead.AESGCM

    def __init__(self, *, key_bits=256, nonce_bits=96):
        self.key_bits, self.nonce_bits = key_bits, nonce_bits
        super().__init__()


class chacha20_poly1305(_aead_cipher_adapter):
    cipher = aead.ChaCha20Poly1305
    key_bits = 256
    nonce_bits = 96


class scrypt:
    def __init__(self, *, length, n=1 << 22, r=8, p=1):
        self.length, self.n, self.r, self.p = length, n, r, p

    def derivation_params(self):
        salt = os.urandom(self.length)
        return salt

    def derive(self, pwd, *, params):
        instance = Scrypt(
            n=self.n,
            r=self.r,
            p=self.p,
            length=self.length,
            salt=params,
            backend=_backend,
        )
        return instance.derive(pwd)


class blake2b:
    def __init__(self, *, length=64):
        self.digest_size = length

    def derivation_params(self):
        key = os.urandom(hashlib.blake2b.MAX_KEY_SIZE)
        return key

    def derive(self, pwd, *, params):
        return hashlib.blake2b(pwd, digest_size=self.digest_size, key=params).digest()

    def mac_params(self):
        key = os.urandom(hashlib.blake2b.MAX_KEY_SIZE)
        return key

    def mac(self, message, *, params):
        return hashlib.blake2b(
            message, digest_size=self.digest_size, key=params
        ).digest()

    def digest(self, data):
        return hashlib.blake2b(data, digest_size=self.digest_size).digest()


class gclmulchunker:

    # Chunk lengths in bytes
    MIN_LENGTH = 128_000
    MAX_LENGTH = 5_120_000

    def __init__(self, *, min_length=MIN_LENGTH, max_length=MAX_LENGTH):
        # Data will be aligned to 4-byte boundaries
        min_length = (min_length + 3) & -4
        if min_length > max_length:
            raise ValueError(
                f'Minimum length ({min_length}) is greater '
                f'than the maximum one ({max_length})'
            )

        self.min_length, self.max_length = min_length, max_length

    def __call__(self, chunk_iterator, *, params=None):
        if not params:
            params = b'\xFF' * 16
        else:
            while len(params) < 16:
                params += params
            params = params[:16]

        chunker = _replicat_adapters._gclmulchunker(
            self.min_length, self.max_length, params
        )
        buffer = b''
        it = iter(chunk_iterator)
        chunk = next(it, None)

        while chunk is not None:
            buffer += chunk
            next_chunk = next(it, None)

            while True:
                pos = chunker.next_cut(buffer, bool(next_chunk is None))
                if not pos:
                    break
                yield buffer[:pos]
                buffer = buffer[pos:]

            chunk = next_chunk

    def chunking_params(self):
        return os.urandom(16)
