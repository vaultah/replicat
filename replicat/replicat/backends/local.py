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

    def upload(self, name, contents):
        destination = self.path / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        # Make sure the temporary is on the same filesystem to make
        # atomic replacements possible
        temp = Path(
            NamedTemporaryFile(
                prefix=f'{destination.name}_', dir=destination.parent, delete=False
            ).name
        )

        if isinstance(contents, io.IOBase):
            with temp.open('wb') as file:
                shutil.copyfileobj(contents, file)
            contents._tracker.close()
        else:
            temp.write_bytes(contents)

        temp.replace(destination)

    def download(self, name):
        contents = (self.path / name).read_bytes()
        return contents

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
                    # NOTE: Anything from the standard library seems
                    # like an overkill here
                    yield file[path_length + 1 :]

    def hide_file(self, name):
        origin = self.path / name
        # NOTE: hidden files should still come up in prefix searches
        origin.replace(origin.with_name(f'{origin.name}_'))


Client = Local
