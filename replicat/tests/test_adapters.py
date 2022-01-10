import os
from collections import Counter
from hashlib import blake2b, scrypt
from random import Random

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from replicat import exceptions
from replicat.utils import adapters


class TestAESGCM:
    @pytest.mark.parametrize('key_bits', [128, 192, 256])
    def test_generate_key(self, key_bits):
        adapter = adapters.aes_gcm(key_bits=key_bits, nonce_bits=96)
        key = adapter.generate_key()
        assert isinstance(key, bytes)
        assert len(key) * 8 == key_bits

    def test_encrypt(self):
        adapter = adapters.aes_gcm(key_bits=256, nonce_bits=96)
        key = b'<key>'.ljust(32, b'\x00')
        return_value = adapter.encrypt(b'<some data>', key)
        ciphertext = AESGCM(key).encrypt(return_value[:12], b'<some data>', None)
        assert return_value[12:] == ciphertext

    def test_decrypt_bad_key(self):
        adapter = adapters.aes_gcm(key_bits=256, nonce_bits=96)
        key = b'<key>'.ljust(32, b'\x00')
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, b'<some data>', None)
        with pytest.raises(exceptions.DecryptionError):
            adapter.decrypt(nonce + ciphertext, b'<bad key>'.ljust(32, b'\x00'))

    def test_decrypt_corrupted(self):
        adapter = adapters.aes_gcm(key_bits=256, nonce_bits=96)
        key = b'<key>'.ljust(32, b'\x00')
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, b'<some data>', None)
        with pytest.raises(exceptions.DecryptionError):
            adapter.decrypt(
                b'\x00' + nonce + ciphertext, b'<bad key>'.ljust(32, b'\x00')
            )

    def test_decrypt(self):
        adapter = adapters.aes_gcm(key_bits=256, nonce_bits=96)
        key = b'<key>'.ljust(32, b'\x00')
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, b'<some data>', None)
        assert adapter.decrypt(nonce + ciphertext, key) == b'<some data>'


class TestChaCha20Poly1305:
    def test_generate_key(self):
        adapter = adapters.chacha20_poly1305()
        key = adapter.generate_key()
        assert isinstance(key, bytes)
        assert len(key) * 8 == 256

    def test_encrypt(self):
        adapter = adapters.chacha20_poly1305()
        key = b'<key>'.ljust(32, b'\x00')
        return_value = adapter.encrypt(b'<some data>', key)
        ciphertext = ChaCha20Poly1305(key).encrypt(
            return_value[:12], b'<some data>', None
        )
        assert return_value[12:] == ciphertext

    def test_decrypt_bad_key(self):
        adapter = adapters.chacha20_poly1305()
        key = b'<key>'.ljust(32, b'\x00')
        nonce = os.urandom(12)
        ciphertext = ChaCha20Poly1305(key).encrypt(nonce, b'<some data>', None)
        with pytest.raises(exceptions.DecryptionError):
            adapter.decrypt(nonce + ciphertext, b'<bad key>'.ljust(32, b'\x00'))

    def test_decrypt_corrupted(self):
        adapter = adapters.chacha20_poly1305()
        key = b'<key>'.ljust(32, b'\x00')
        nonce = os.urandom(12)
        ciphertext = ChaCha20Poly1305(key).encrypt(nonce, b'<some data>', None)
        with pytest.raises(exceptions.DecryptionError):
            adapter.decrypt(
                b'\x00' + nonce + ciphertext, b'<bad key>'.ljust(32, b'\x00')
            )

    def test_decrypt(self):
        adapter = adapters.chacha20_poly1305()
        key = b'<key>'.ljust(32, b'\x00')
        nonce = os.urandom(12)
        ciphertext = ChaCha20Poly1305(key).encrypt(nonce, b'<some data>', None)
        assert adapter.decrypt(nonce + ciphertext, key) == b'<some data>'


class TestScrypt:
    def test_generate_derivation_params(self):
        adapter = adapters.scrypt(length=17, n=4, r=8, p=1)
        params = adapter.generate_derivation_params()
        assert isinstance(params, bytes)
        assert len(params) == 17

    def test_derive_without_context(self):
        adapter = adapters.scrypt(length=17, n=4, r=8, p=1)
        params = adapter.generate_derivation_params()
        key = adapter.derive(b'<password>', params=params)
        assert key == scrypt(b'<password>', n=4, r=8, p=1, dklen=17, salt=params)

    def test_derive_with_context(self):
        adapter = adapters.scrypt(length=17, n=4, r=8, p=1)
        params = adapter.generate_derivation_params()
        key = adapter.derive(
            b'<password>', context=b'<additional context>', params=params
        )
        assert key == scrypt(
            b'<password>',
            n=4,
            r=8,
            p=1,
            dklen=17,
            salt=params + b'<additional context>',
        )


class TestBlake2B:
    def test_generate_derivation_params(self):
        adapter = adapters.blake2b(length=17)
        params = adapter.generate_derivation_params()
        assert isinstance(params, bytes)
        assert len(params) == blake2b.SALT_SIZE

    def test_derive_without_context(self):
        adapter = adapters.blake2b(length=17)
        params = adapter.generate_derivation_params()
        key = adapter.derive(b'<key material>', params=params)
        assert (
            key == blake2b(key=b'<key material>', salt=params, digest_size=17).digest()
        )

    def test_derive_with_context(self):
        adapter = adapters.blake2b(length=17)
        params = adapter.generate_derivation_params()
        key = adapter.derive(
            b'<key material>', context=b'<additional context>', params=params
        )
        assert (
            key
            == blake2b(
                b'<additional context>',
                key=b'<key material>',
                salt=params,
                digest_size=17,
            ).digest()
        )

    def test_generate_mac_params(self):
        adapter = adapters.blake2b(length=17)
        params = adapter.generate_mac_params()
        assert isinstance(params, bytes)
        assert len(params) == blake2b.MAX_KEY_SIZE

    def test_mac(self):
        adapter = adapters.blake2b(length=17)
        params = adapter.generate_mac_params()
        mac = adapter.mac(b'<data>', params=params)
        assert mac == blake2b(b'<data>', digest_size=17, key=params).digest()

    def test_digest(self):
        adapter = adapters.blake2b(length=17)
        digest = adapter.digest(b'<data>')
        assert digest == blake2b(b'<data>', digest_size=17).digest()


class TestGCLMULChunker:
    @pytest.mark.parametrize(
        'min_length, max_length, inputs, sizes',
        [
            (5, 10, [], []),
            (5, 10, [b'\xaa' * 5], [5]),
            (5, 10, [b'\xaa' * 6], [6]),
            (5, 10, [b'\xaa' * 10], [10]),
            (5, 10, [b'\xaa' * 11], [5, 6]),
            (5, 10, [b'\xaa' * 12], [6, 6]),
            (5, 10, [b'\xaa' * 13], [6, 7]),
            (5, 10, [b'\xaa' * 14], [7, 7]),
            (5, 10, [b'\xaa' * 15], [10, 5]),
            (5, 10, [b'\xaa' * 16], [10, 6]),
            (5, 10, [b'\xaa' * 17], [10, 7]),
            (5, 10, [b'\xaa' * 18], [10, 8]),
            (5, 10, [b'\xaa' * 19], [10, 9]),
            (4, 4, [b'\xaa'] * 20, [4] * 5),
            (4, 4, [b'\xaa' * 20], [4] * 5),
            (10, 12, [b'\xaa'] * 11, [11]),
        ],
    )
    def test_small_inputs_with_alignment(self, min_length, max_length, inputs, sizes):
        chunker = adapters.gclmulchunker(min_length=min_length, max_length=max_length)
        chunks = list(chunker(inputs))
        assert b''.join(chunks) == b''.join(inputs)
        assert [len(x) for x in chunks] == list(sizes)

    def test_personalization(self):
        rnd = Random(0)
        data = rnd.randbytes(1_000_000)
        person = bytearray(rnd.randbytes(16))
        chunker = adapters.gclmulchunker(min_length=500, max_length=10_000)
        chunks = list(chunker([data], params=bytes(person)))

        person[0] = (person[0] - 1) % 255
        person_chunker = adapters.gclmulchunker(min_length=500, max_length=10_000)
        person_chunks = list(person_chunker([data], params=bytes(person)))

        assert person_chunks != chunks
        assert b''.join(chunks) == b''.join(person_chunks) == data

    # Hand-picked values
    @pytest.mark.parametrize('seed', [507, 11219, 25750, 31286])
    def test_sequence_stabilizes(self, seed):
        rnd = Random(seed)
        data = bytearray(rnd.randbytes(1_000_000))
        person = rnd.randbytes(16)
        before_chunker = adapters.gclmulchunker(min_length=500, max_length=10_000)
        before_chunks = list(before_chunker([data], params=person))

        data[0] = (data[0] - 1) % 255
        after_chunker = adapters.gclmulchunker(min_length=500, max_length=10_000)
        after_chunks = list(after_chunker([data], params=person))

        i, j = len(before_chunks), len(after_chunks)
        while before_chunks[i - 1] == after_chunks[j - 1]:
            i -= 1
            j -= 1

        assert 0 < i < 4
        assert 0 < j < 4
        assert b''.join(before_chunks[:i])[1:] == b''.join(after_chunks[:j])[1:]
        assert data.startswith(b''.join(after_chunks[:j]))

    @pytest.mark.parametrize(
        'seed, size', [(0, 1_001), (1, 2_000), (2, 497), (2, 4_023), (3, 5_001)]
    )
    def test_repetition(self, seed, size):
        rnd = Random(seed)
        repeated_data = bytearray(rnd.randbytes(size))
        person = rnd.randbytes(16)

        chunker = adapters.gclmulchunker(min_length=500, max_length=10_000)
        chunks_50 = list(chunker([repeated_data] * 50, params=person))
        assert b''.join(chunks_50) == repeated_data * 50

        # Establish a pattern
        counts_50 = Counter()
        for x in chunks_50:
            counts_50[x] += 1

        chunk_pattern = [k for k, v in counts_50.items() if v > 1]
        assert 0 < len(chunk_pattern) < 4
        assert 1 < len(counts_50) - len(chunk_pattern) < 4

        # Make sure we observe the same pattern in longer sequences
        chunks_100 = list(chunker([repeated_data] * 100, params=person))
        assert b''.join(chunks_100) == repeated_data * 100
        unique_chunks_100 = set(chunks_100)
        assert unique_chunks_100.issuperset(chunk_pattern)
        assert len(unique_chunks_100) - len(chunk_pattern) < 4

    def test_generate_chunking_params(self):
        chunker = adapters.gclmulchunker(min_length=500, max_length=10_000)
        params = chunker.generate_chunking_params()
        assert isinstance(params, bytes)
        assert len(params) == 16
