import logging
import os
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile

import backoff

from .. import Backend
from ..utils.fs import iterative_scandir

logger = logging.getLogger(__name__)
backoff_on_oserror = backoff.on_exception(backoff.fibo, OSError, max_value=5)


class Local(Backend):
    def __init__(self, connection_string):
        self.path = Path(connection_string)

    @backoff_on_oserror
    def exists(self, name):
        return os.path.exists(self.path / name)

    def _destination_temp(self, name):
        destination = self.path / name
        destination.parent.mkdir(parents=True, exist_ok=True)

        shortened_name = destination.name[:240]
        # Make sure the temporary is on the same filesystem to make
        # atomic replacements possible
        temp = Path(
            NamedTemporaryFile(
                prefix=f'{shortened_name}_',
                suffix='.tmp',
                dir=destination.parent,
                delete=False,
            ).name
        )
        return destination, temp

    @backoff_on_oserror
    def upload(self, name, data):
        destination, temp = self._destination_temp(name)
        try:
            temp.write_bytes(data)
            # os.replace may throw a PermissionError on Windows if the target is
            # replaced simultaneously from multiple threads (in CI, at least)
            temp.replace(destination)
        except BaseException:
            temp.unlink(missing_ok=True)
            raise

    @backoff_on_oserror
    def upload_stream(self, name, stream, length):
        destination, temp = self._destination_temp(name)
        try:
            with temp.open('wb') as file:
                shutil.copyfileobj(stream, file)
            temp.replace(destination)
        except BaseException:
            temp.unlink(missing_ok=True)
            stream.seek(0)
            raise

    @backoff_on_oserror
    def download(self, name):
        return (self.path / name).read_bytes()

    @backoff_on_oserror
    def list_files(self, prefix=''):
        path_length = len(str(self.path))
        # pathlib strips the trailing slash from paths; we don't want that here
        prefix_dirname, prefix_basename = os.path.split(prefix)
        absolute_dirname = self.path / prefix_dirname

        try:
            scandir = os.scandir(absolute_dirname)
        except OSError:
            logger.debug(f'Unable to list files in {absolute_dirname}', exc_info=True)
            return

        with scandir as it:
            for entry in it:
                if not entry.name.startswith(prefix_basename):
                    continue

                if entry.is_dir():
                    subentries = iterative_scandir(entry)
                elif entry.is_file():
                    subentries = [entry]
                else:
                    continue

                for path in map(os.fspath, subentries):
                    # Exclude temporary files
                    if path.endswith('.tmp'):
                        continue

                    # NOTE: Anything from the standard library seems
                    # like an overkill here
                    path = path.replace(os.sep, '/')
                    yield path[path_length + 1 :]

    @backoff_on_oserror
    def delete(self, name):
        (self.path / name).unlink(missing_ok=True)

    def _find_deletable(self, start):
        with os.scandir(start) as it:
            for entry in it:
                if entry.is_dir():
                    empty = True
                    for subentry, subempty in self._find_deletable(entry.path):
                        yield subentry, subempty
                        if not subempty:
                            empty = False
                else:
                    empty = False

                yield entry, empty

    @backoff_on_oserror
    def clean(self):
        for entry, empty in self._find_deletable(self.path):
            if empty:
                os.rmdir(entry)


Client = Local
