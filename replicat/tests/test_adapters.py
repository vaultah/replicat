import os
from hashlib import blake2b, scrypt

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from replicat import exceptions
from replicat.utils import adapters


class TestAESGCM:
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
    def test_derive(self):
        adapter = adapters.scrypt(length=17, n=4, r=8, p=1)
        params = adapter.derivation_params()
        key = adapter.derive(b'<password>', params=params)
        assert key == scrypt(b'<password>', n=4, r=8, p=1, dklen=17, salt=params)


class TestBlake2B:
    def test_derive(self):
        adapter = adapters.blake2b(length=17)
        params = adapter.derivation_params()
        key = adapter.derive(b'<password>', params=params)
        assert key == blake2b(b'<password>', digest_size=17, key=params).digest()

    def test_mac(self):
        adapter = adapters.blake2b(length=17)
        params = adapter.mac_params()
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
            (5, 10, [b'\xaa' * 15], [7, 8]),
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
        data = os.urandom(1_000_000)
        chunker = adapters.gclmulchunker(min_length=500, max_length=10_000)
        chunks = list(chunker([data]))

        person_chunker = adapters.gclmulchunker(min_length=500, max_length=10_000)
        person_chunks = list(person_chunker([data], params=os.urandom(16)))

        assert person_chunks != chunks
        assert b''.join(chunks) == b''.join(person_chunks) == data

    @pytest.mark.parametrize('person', [None, b'', b'abcd', os.urandom(64)])
    def test_sequence_stabilizes(self, person):
        data = bytearray(os.urandom(1_000_000))
        before_chunker = adapters.gclmulchunker(min_length=500, max_length=10_000)
        before_chunks = list(before_chunker([data], params=person))

        data[0] = (data[0] - 1) % 255
        after_chunker = adapters.gclmulchunker(min_length=500, max_length=10_000)
        after_chunks = list(after_chunker([data], params=person))

        assert before_chunks[-1] == after_chunks[-1]

    @pytest.mark.parametrize('person', [None, b'', b'abcd', os.urandom(64)])
    @pytest.mark.parametrize('repeating_bytes', [1_500, 5_000, 20_000, 50_000])
    def test_repetition(self, person, repeating_bytes):
        data = os.urandom(repeating_bytes)
        counts = []

        for i in (10, 20, 30):
            chunker = adapters.gclmulchunker(min_length=500, max_length=10_000)
            chunks = list(chunker([data] * i))
            counts.append((len(chunks), len(set(chunks))))

        first, second, third = counts
        assert first[0] < second[0] < third[0]
        assert first[1] == second[1] == second[1]
