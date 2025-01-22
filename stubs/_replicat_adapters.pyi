from typing import ByteString

class _gclmulchunker:
    min_length: int
    max_length: int

    def __init__(self, min_length: int, max_length: int, key: ByteString) -> None: ...
    def next_cut(self, chunk: ByteString, final: bool = False) -> int: ...
