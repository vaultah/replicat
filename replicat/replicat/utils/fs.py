import os
from pathlib import Path


def recursive_scandir(start_entry):
    # Just recursively yield all *files* below `start_entry`
    if not start_entry.is_dir(follow_symlinks=False):
        yield start_entry.path
    else:
        with os.scandir(start_entry.path) as it:
            for entry in it:
                yield from recursive_scandir(entry)


def flatten_paths(paths):
    for path in paths:
        try:
            scandir = os.scandir(path)
        except NotADirectoryError:
            yield path
        else:
            with scandir as it:
                for entry in it:
                    yield from map(Path, recursive_scandir(entry))


def stream_files(files, *, chunk_size=16_777_216):
    for f in files:
        file = f.open('rb')
        for chunk in iter(lambda: file.read(chunk_size), b''):
            yield chunk
