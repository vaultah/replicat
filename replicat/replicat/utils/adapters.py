import hashlib
import inspect
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

_backend = default_backend()


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


class aes_gcm(_cipher_adapter):
    cipher = aead.AESGCM
    def __init__(self, *, key_bits=256, nonce_bits=96):
        self.key_bits, self.nonce_bits = key_bits, nonce_bits
        super().__init__()


class chacha20_poly1305(_cipher_adapter):
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
        instance = Scrypt(n=self.n, r=self.r, p=self.p, length=self.length,
                        salt=params, backend=_backend)
        return instance.derive(pwd)


class blake2b:

    def __init__(self, *, length=64):
        self.digest_size = length

    def derivation_params(self):
        key = os.urandom(hashlib.blake2b.MAX_KEY_SIZE)
        return key

    def derive(self, pwd, *, params):
        return hashlib.blake2b(pwd, digest_size=self.digest_size,
                            key=params).digest()

    def mac_params(self):
        key = os.urandom(hashlib.blake2b.MAX_KEY_SIZE)
        return key

    def mac(self, message, *, params):
        return hashlib.blake2b(message, digest_size=self.digest_size,
                            key=params).digest()


class simple_chunker:

    # Chunk lengths in bytes
    MIN_LENGTH = 128_000
    MAX_LENGTH = 25_000_000

    def __init__(self, *, min_length=MIN_LENGTH, max_length=MAX_LENGTH):
        if min_length > max_length:
            raise ValueError('Minimum length is greater than the maximum one')

        self.min_length, self.max_length = min_length, max_length
        self.buffer = b''

    def _fnv_1a(self, buffer):
        hsh = 0xCBF2_9CE4_8422_2325
        for x in buffer:
            hsh ^= x
            hsh = (hsh * 0x0000_0100_0000_01B3) & 0xFFFF_FFFF_FFFF_FFFF

        return hsh

    def _next_from_buffer(self, *, person=None):
        if person is None:
            person = b''

        person = person.rjust(64, b'\x00')
        seed = self._fnv_1a(person + self.buffer[: self.min_length])
        cut_at = max(
            range(self.min_length - 1, min(self.max_length, len(self.buffer)), 8),
            key=lambda i: int.from_bytes(self.buffer[i : i + 8], 'little')
            ^ int.from_bytes(self.buffer[i - 8 : i], 'little') ^ seed,
            default=self.min_length - 1,
        )
        rv = self.buffer[: cut_at + 1]
        self.buffer = self.buffer[cut_at + 1 :]
        return rv

    def next_chunks(self, chunk_iterator, *, params=None):
        it = iter(chunk_iterator)
        chunk = next(it, None)

        while chunk is not None:
            self.buffer += chunk
            next_chunk = next(it, None)

            while len(self.buffer) // self.max_length > (next_chunk is None):
                yield self._next_from_buffer(person=params)

            chunk = next_chunk

    def finalize(self):
        if len(self.buffer) <= self.max_length:
            chunks = [self.buffer]
            self.buffer = b''
        elif len(self.buffer) < self.max_length + self.min_length:
            # TODO: something better for weirder limits?
            chunks = [
                self.buffer[:len(self.buffer) // 2],
                self.buffer[len(self.buffer) // 2:]
            ]
            self.buffer = b''
        else:
            chunks = [self.buffer[:self.max_length]]
            self.buffer = self.buffer[self.max_length:]

            while self.buffer:
                div, mod = divmod(len(self.buffer), self.min_length)
                cut_at = self.min_length + mod // div
                chunks.append(self.buffer[:cut_at])
                self.buffer = self.buffer[cut_at:]

        return chunks

    def chunking_params(self):
        person = os.urandom(64)
        return person
