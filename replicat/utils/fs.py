import errno
import os
import os.path
from pathlib import Path

from appdirs import user_cache_dir

DEFAULT_CACHE_DIRECTORY = user_cache_dir('replicat', 'replicat')
DEFAULT_STREAM_CHUNK_SIZE = 16_777_216


# Inspired by shutil
if hasattr(os, 'listxattr'):

    def read_xattrs(path):
        xattrs = {}
        try:
            names = os.listxattr(path)
        except OSError as e:
            if e.errno not in (errno.ENOTSUP, errno.ENODATA, errno.EINVAL):
                raise
        else:
            for name in names:
                try:
                    value = os.getxattr(path, name)
                except OSError as e:
                    if e.errno not in (errno.ENOTSUP, errno.ENODATA, errno.EINVAL):
                        raise
                else:
                    xattrs[name] = value

        return xattrs

    def set_xattrs(path, attrs):
        for name, value in attrs.items():
            try:
                os.setxattr(path, name, value)
            except OSError as e:
                if e.errno not in (
                    errno.EPERM,
                    errno.ENOTSUP,
                    errno.ENODATA,
                    errno.EINVAL,
                ):
                    raise

else:

    def read_xattrs(path):
        return None

    def set_xattrs(path, attrs):
        pass


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
