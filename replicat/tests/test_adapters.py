import os

import pytest
from replicat.utils import adapters



class TestSimpleChunker:

    @pytest.mark.parametrize('min_length, max_length, inputs, sizes', [
        (5, 7, [], [0]),
        (5, 7, [b'\xaa' * 5], [5]),
        (5, 7, [b'\xaa' * 6], [6]),
        (5, 7, [b'\xaa' * 7], [7]),
        (5, 7, [b'\xaa' * 8], [4, 4]),
        (5, 7, [b'\xaa' * 12], [7, 5]),
        (5, 7, [b'\xaa' * 13], [7, 6]),
        (5, 7, [b'\xaa' * 14], [5, 4, 5]),
        (5, 7, [b'\xaa' * 15], [5, 5, 5]),
        (1, 1, [b'\xaa'] * 20, [1] * 20),
        (10, 10, [b'\xaa'] * 9, [9]),

    ])
    def test_chunk_generator(self, min_length, max_length, inputs, sizes):
        chunker = adapters.simple_chunker(min_length=min_length, max_length=max_length)
        chunks = list(chunker.next_chunks(inputs))
        chunks += chunker.finalize()
        assert b''.join(chunks) == b''.join(inputs)
        assert [len(x) for x in chunks] == list(sizes)

    def test_personalization(self):
        data = os.urandom(1_000_000)
        chunker = adapters.simple_chunker(min_length=500, max_length=10000)
        chunks = list(chunker.next_chunks([data])) + chunker.finalize()

        person_chunker = adapters.simple_chunker(
            min_length=500, max_length=10000
        )
        person_chunks = list(
            person_chunker.next_chunks([data], params=os.urandom(10))
        )
        person_chunks += person_chunker.finalize()

        assert person_chunks != chunks
        assert b''.join(chunks) == b''.join(person_chunks) == data

    @pytest.mark.parametrize('person', [None, b'', b'abcd', os.urandom(64)])
    def test_sequence_stabilizes(self, person):
        data = bytearray(os.urandom(1_000_000))
        before_chunker = adapters.simple_chunker(min_length=500, max_length=10000)
        before_chunks = list(before_chunker.next_chunks([data], params=person))
        before_chunks += before_chunker.finalize()

        data[0] = (data[0] - 1) % 255
        after_chunker = adapters.simple_chunker(min_length=500, max_length=10000)
        after_chunks = list(after_chunker.next_chunks([data], params=person))
        after_chunks += after_chunker.finalize()

        matches = next(
            i
            for i, (x, y) in enumerate(zip(before_chunks[::-1], after_chunks[::-1]))
            if x != y
        )
        assert len(before_chunks) == len(before_chunks)
        assert matches == len(before_chunks) - 1
