import os
from pathlib import Path


def recursive_scandir(start_entry, *, follow_symlinks=False):
    # Just recursively yield all *files* below `start_entry`
    if not start_entry.is_dir(follow_symlinks=follow_symlinks):
        yield start_entry.path
    else:
        with os.scandir(start_entry.path) as it:
            for entry in it:
                yield from recursive_scandir(entry, follow_symlinks=follow_symlinks)


def flatten_paths(paths, *, follow_symlinks=False):
    for path in paths:
        try:
            scandir = os.scandir(path)
        except NotADirectoryError:
            yield path
        else:
            with scandir as it:
                for entry in it:
                    recurse = recursive_scandir(entry, follow_symlinks=follow_symlinks)
                    yield from map(Path, recurse)


def stream_files(files, *, chunk_size=16_777_216):
    for file in files:
        with file.open('rb') as obj:
            while True:
                chunk = obj.read(chunk_size)
                yield file, chunk
                if not chunk:
                    break
