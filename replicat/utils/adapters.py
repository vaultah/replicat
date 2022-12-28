from __future__ import annotations

import hashlib
import os
from abc import ABC, abstractmethod
from collections.abc import ByteString, Iterator
from typing import Optional

import cryptography.exceptions
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import _replicat_adapters
from .. import exceptions


class CipherAdapter(ABC):
    @abstractmethod
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data using the provided key"""
        return b''

    @abstractmethod
    def decrypt(self, data: bytes, key: bytes) -> bytes:
        """Decrypt data using the provided key"""
        return b''

    @property
    @abstractmethod
    def key_bytes(self) -> int:
        """Return the number of bytes in a key"""
        return 0

    def generate_key(self) -> bytes:
        return os.urandom(self.key_bytes)


class KDFAdapter(ABC):
    @abstractmethod
    def generate_derivation_params(self) -> bytes:
        """Generate derivation params for the KDF"""
        return b''

    @abstractmethod
    def derive(
        self, key_material: bytes, *, params: bytes, context: Optional[bytes] = None
    ) -> bytes:
        """Derive key from IKM using the provided params. The optional context
        argument enables you to generate subkeys from the master key (IKM)"""
        return b''


class MACAdapter(ABC):
    @abstractmethod
    def generate_mac_params(self) -> bytes:
        """Generate key for the MAC"""
        return b''

    @abstractmethod
    def mac(self, message: bytes, *, params: bytes) -> bytes:
        """Generate MAC using the provided params (key)"""
        return b''


class IncrementalHasher(ABC):
    def feed(self, data: bytes) -> None:
        return None

    def digest(self) -> bytes:
        return b''


class HashAdapter(ABC):
    @abstractmethod
    def digest(self, data: bytes) -> bytes:
        """Compute the hash digest from data"""
        return b''

    @abstractmethod
    def incremental_hasher(self) -> IncrementalHasher:
        raise NotImplementedError


class ChunkerAdapter(ABC):
    @property
    @abstractmethod
    def alignment(self) -> Optional[int]:
        """Return the alignment"""
        return 0

    @abstractmethod
    def generate_chunking_params(self) -> bytes:
        """Generate chunking params"""
        return b''

    @abstractmethod
    def __call__(
        self,
        chunk_iterator: Iterator[ByteString],
        *,
        params: Optional[ByteString] = None,
    ) -> Iterator[bytes]:
        """Re-chunk the incoming stream of bytes using the provided params"""
        yield b''


class HashlibIncrementalHasher(IncrementalHasher):
    def __init__(self, hash_instance):
        self.instance = hash_instance

    def feed(self, data: bytes) -> None:
        self.instance.update(data)

    def digest(self) -> bytes:
        return self.instance.digest()


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

    def generate_derivation_params(self):
        salt = os.urandom(self.length)
        return salt

    def derive(self, pwd, *, params, context=None):
        if context is None:
            context = b''

        # If we used hashlib's scrypt, we'd need to take care of maxmem limits
        # ourselves, plus they are small
        instance = Scrypt(
            n=self.n,
            r=self.r,
            p=self.p,
            length=self.length,
            salt=params + context,
        )
        return instance.derive(pwd)


class blake2b(KDFAdapter, MACAdapter, HashAdapter):
    def __init__(self, *, length=64):
        self.digest_size = length

    def generate_derivation_params(self):
        salt = os.urandom(hashlib.blake2b.SALT_SIZE)
        return salt

    def derive(self, key_material, *, params, context=None):
        if context is None:
            context = b''

        return hashlib.blake2b(
            context, salt=params, digest_size=self.digest_size, key=key_material
        ).digest()

    def generate_mac_params(self):
        key = os.urandom(hashlib.blake2b.MAX_KEY_SIZE)
        return key

    def mac(self, message, *, params):
        return hashlib.blake2b(
            message, digest_size=self.digest_size, key=params
        ).digest()

    def digest(self, data):
        return hashlib.blake2b(data, digest_size=self.digest_size).digest()

    def incremental_hasher(self):
        return HashlibIncrementalHasher(hashlib.blake2b(digest_size=self.digest_size))


class sha2(HashAdapter):
    def __init__(self, *, bits=256):
        if bits not in (224, 256, 384, 512):
            raise ValueError('Invalid digest size')
        self._hasher_class = getattr(hashlib, f'sha{bits}')

    def digest(self, data):
        return self._hasher_class(data).digest()

    def incremental_hasher(self):
        return HashlibIncrementalHasher(self._hasher_class())


class sha3(HashAdapter):
    def __init__(self, *, bits=256):
        if bits not in (224, 256, 384, 512):
            raise ValueError('Invalid digest size')
        self._hasher_class = getattr(hashlib, f'sha3_{bits}')

    def digest(self, data):
        return self._hasher_class(data).digest()

    def incremental_hasher(self):
        return HashlibIncrementalHasher(self._hasher_class())


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
        buffer = bytearray()
        it = iter(chunk_iterator)
        chunk = next(it, None)

        while chunk is not None:
            buffer += chunk
            next_chunk = next(it, None)

            while True:
                pos = chunker.next_cut(buffer, bool(next_chunk is None))
                if not pos:
                    break
                yield bytes(buffer[:pos])
                del buffer[:pos]

            chunk = next_chunk

    def generate_chunking_params(self):
        return os.urandom(16)
