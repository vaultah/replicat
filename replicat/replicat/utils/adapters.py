import hashlib
import os
from abc import ABC, abstractmethod
from typing import Iterator, Optional

import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import _replicat_adapters
from .. import exceptions

_backend = default_backend()


class CipherAdapter(ABC):
    @abstractmethod
    def encrypt(self, data: bytes, key: bytes):
        """Encrypt data using the provided key"""
        return b''

    @abstractmethod
    def decrypt(self, data: bytes, key: bytes):
        """Decrypt data using the provided key"""
        return b''

    @property
    @abstractmethod
    def key_bytes(self):
        """Return the number of bytes in a key"""
        return 0


class KDFAdapter(ABC):
    @abstractmethod
    def derivation_params(self) -> bytes:
        """Generate derivation params for the KDF"""
        return b''

    @abstractmethod
    def derive(self, pwd: bytes, *, params: bytes) -> bytes:
        """Derive key from password using the provided params"""
        return b''


class MACAdapter(ABC):
    @abstractmethod
    def mac_params(self) -> bytes:
        """Generate key for the MAC"""
        return b''

    @abstractmethod
    def mac(self, message: bytes, *, params: bytes) -> bytes:
        """Generate MAC using the provided params (key)"""
        return b''


class HashAdapter(ABC):
    @abstractmethod
    def digest(self, data: bytes) -> bytes:
        """Compute the hash digest from data"""
        return b''


class ChunkerAdapter(ABC):
    @abstractmethod
    def chunking_params(self) -> bytes:
        """Generate chunking params"""
        return b''

    @abstractmethod
    def __call__(
        self, chunk_iterator: Iterator[bytes], *, params: Optional[bytes] = None
    ):
        """Re-chunk the incoming stream of bytes using the provided params"""
        yield b''

    @property
    @abstractmethod
    def alignment(self):
        """Return the alignment"""
        return 0


class AEADCipherAdapterMixin(CipherAdapter):
    cipher = None

    def __init__(self):
        self._key_bytes, self._nonce_bytes = self.key_bits // 8, self.nonce_bits // 8

    def encrypt(self, data, key):
        cipher = self.cipher(key)
        nonce = os.urandom(self._nonce_bytes)
        return nonce + cipher.encrypt(nonce, data, None)

    def decrypt(self, data, key):
        cipher = self.cipher(key)
        nonce, ciphertext = data[: self._nonce_bytes], data[self._nonce_bytes :]
        try:
            return cipher.decrypt(nonce, ciphertext, None)
        except cryptography.exceptions.InvalidTag as e:
            raise exceptions.DecryptionError from e

    @property
    def key_bytes(self):
        return self._key_bytes


class aes_gcm(AEADCipherAdapterMixin):
    cipher = aead.AESGCM

    def __init__(self, *, key_bits=256, nonce_bits=96):
        self.key_bits, self.nonce_bits = key_bits, nonce_bits
        super().__init__()


class chacha20_poly1305(AEADCipherAdapterMixin):
    cipher = aead.ChaCha20Poly1305
    key_bits = 256
    nonce_bits = 96


class scrypt(KDFAdapter):
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


class blake2b(KDFAdapter, MACAdapter, HashAdapter):
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


class gclmulchunker(ChunkerAdapter):

    # Chunk lengths in bytes
    MIN_LENGTH = 128_000
    MAX_LENGTH = 5_120_000
    alignment = 4

    def __init__(self, *, min_length=MIN_LENGTH, max_length=MAX_LENGTH):
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
