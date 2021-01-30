import os

import pytest

from replicat.utils import adapters


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
    def test_repetion(self, person, repeating_bytes):
        data = os.urandom(repeating_bytes)
        counts = []

        for i in (10, 20, 30):
            chunker = adapters.gclmulchunker(min_length=500, max_length=10_000)
            chunks = list(chunker([data] * i))
            counts.append((len(chunks), len(set(chunks))))

        first, second, third = counts
        assert first[0] < second[0] < third[0]
        assert first[1] == second[1] == second[1]
