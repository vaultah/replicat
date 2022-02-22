import os
import os.path
from pathlib import Path

DEFAULT_STREAM_CHUNK_SIZE = 16_777_216


def iterative_scandir(path, *, follow_symlinks=False):
    """Yield *files* under path recursively"""
    stack = [path]

    while stack:
        start = stack.pop()
        with os.scandir(start) as it:
            for entry in it:
                if entry.is_dir(follow_symlinks=follow_symlinks):
                    stack.append(entry)
                elif entry.is_file(follow_symlinks=follow_symlinks):
                    yield entry


def flatten_paths(paths):
    for path in paths:
        path = Path(path)
        if path.is_dir():
            yield from map(Path, iterative_scandir(path, follow_symlinks=True))
        elif path.is_file():
            yield path


def stream_files(files, *, chunk_size=DEFAULT_STREAM_CHUNK_SIZE):
    for path in files:
        with path.open('rb') as file:
            while True:
                chunk = file.read(chunk_size)
                yield path, chunk
                if len(chunk) < chunk_size:
                    break
