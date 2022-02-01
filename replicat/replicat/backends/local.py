import io
import logging
import os
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile

from .. import Backend
from ..utils.fs import recursive_scandir

logger = logging.getLogger(__name__)


class Local(Backend):
    def __init__(self, connection_string):
        self.path = Path(connection_string)

    def exists(self, name):
        return os.path.exists(self.path / name)

    def upload(self, name, data):
        destination = self.path / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        # Make sure the temporary is on the same filesystem to make
        # atomic replacements possible
        temp = Path(
            NamedTemporaryFile(
                prefix=f'{destination.name}_',
                suffix='.tmp',
                dir=destination.parent,
                delete=False,
            ).name
        )

        try:
            if isinstance(data, io.BytesIO):
                with temp.open('wb') as file:
                    shutil.copyfileobj(data, file)
            else:
                temp.write_bytes(data)

            temp.replace(destination)
        except BaseException:
            temp.unlink(missing_ok=True)
            raise

    def download(self, name):
        return (self.path / name).read_bytes()

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

                for file in recursive_scandir(entry):
                    # Exclude temporary files
                    if file.endswith('.tmp'):
                        continue

                    # NOTE: Anything from the standard library seems
                    # like an overkill here
                    yield file[path_length + 1 :]

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

    def clean(self):
        for entry, empty in self._find_deletable(self.path):
            if empty:
                os.rmdir(entry)


Client = Local
