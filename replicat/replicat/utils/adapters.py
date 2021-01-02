import hashlib
import os
import struct

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
        nonce, ciphertext = data[: self.nonce_bytes], data[self.nonce_bytes :]
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


class simple_chunker:

    # Chunk lengths in bytes
    MIN_LENGTH = 128_000
    MAX_LENGTH = 8_192_000

    def __init__(self, *, min_length=MIN_LENGTH, max_length=MAX_LENGTH):
        if min_length > max_length:
            raise ValueError('Minimum length is greater than the maximum one')

        self.min_length, self.max_length = min_length, max_length

    def _fnv_1a_from_bytes(self, buffer):
        rv = 0xCBF2_9CE4_8422_2325
        for x in buffer:
            rv ^= x
            rv = (rv * 0x0000_0100_0000_01B3) & 0xFFFF_FFFF_FFFF_FFFF

        return rv

    def _fnv_1a_from_int32_with_xor_fold(self, buffer32, basis):
        basis ^= buffer32 & 0xFF
        basis = (basis * 0x0000_0100_0000_01B3) & 0xFFFF_FFFF_FFFF_FFFF

        basis ^= buffer32 >> 8 & 0xFF
        basis = (basis * 0x0000_0100_0000_01B3) & 0xFFFF_FFFF_FFFF_FFFF

        basis ^= buffer32 >> 16 & 0xFF
        basis = (basis * 0x0000_0100_0000_01B3) & 0xFFFF_FFFF_FFFF_FFFF

        basis ^= buffer32 >> 24
        basis = (basis * 0x0000_0100_0000_01B3) & 0xFFFF_FFFF_FFFF_FFFF
        return (basis >> 32) ^ basis & 0xFFFF_FFFF

    def _next_cut(self, buffer, *, offset_basis):
        def _key(
            i,
            _unpack_from=struct.unpack_from,
            _fnv=self._fnv_1a_from_int32_with_xor_fold,
            _buffer=buffer,
            _basis=offset_basis,
        ):
            prev, cur = _unpack_from('<LL', _buffer, offset=i - 4)
            return _fnv(prev ^ cur, _basis)

        start_index = (self.min_length + 3) & -4
        return max(
            range(start_index, min(self.max_length, len(buffer)), 4),
            key=_key,
            default=start_index,
        )

    def _finalize(self, buffer):
        if len(buffer) <= self.max_length:
            chunks = [buffer]
        elif len(buffer) < self.max_length + self.min_length:
            # TODO: something better for weirder limits?
            chunks = [buffer[: len(buffer) // 2], buffer[len(buffer) // 2 :]]
        else:
            chunks = [buffer[: self.max_length], buffer[self.max_length :]]

        return chunks

    def __call__(self, chunk_iterator, *, params=None):
        if not params:
            params = b''
        else:
            while len(params) < 64:
                params += params
            params = params[:64]

        offset_basis = self._fnv_1a_from_bytes(params)
        buffer = b''
        it = iter(chunk_iterator)
        chunk = next(it, None)

        while chunk is not None:
            buffer += chunk
            next_chunk = next(it, None)

            while len(buffer) // self.max_length > (next_chunk is None):
                pos = self._next_cut(buffer, offset_basis=offset_basis)
                yield buffer[:pos]
                buffer = buffer[pos:]

            chunk = next_chunk

        yield from self._finalize(buffer)

    def chunking_params(self):
        return os.urandom(64)
