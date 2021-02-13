import os
from pathlib import Path

from appdirs import user_cache_dir

CACHE_DIRECTORY = user_cache_dir('replicat', 'replicat')


def recursive_scandir(start_entry, *, follow_symlinks=False):
    # Just recursively yield all *files* below `start_entry`
    if start_entry.is_file(follow_symlinks=follow_symlinks):
        yield start_entry.path
    elif start_entry.is_dir(follow_symlinks=follow_symlinks):
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


def list_cached(path):
    start = Path(CACHE_DIRECTORY, path)
    start.mkdir(parents=True, exist_ok=True)

    for path in flatten_paths([start]):
        yield path.relative_to(CACHE_DIRECTORY)


def get_cached(path):
    return Path(CACHE_DIRECTORY, path).read_bytes()


def store_cached(path, data):
    file = Path(CACHE_DIRECTORY, path)
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_bytes(data)
