import pytest

from replicat.backends import local
from replicat.repository import Repository
from replicat.utils.compat import Random


@pytest.fixture
def local_backend(tmp_path):
    return local.Client(tmp_path / Random().randbytes(4).hex())


@pytest.fixture
def local_repo(local_backend, tmp_path):
    return Repository(local_backend, concurrent=5, cache_directory=tmp_path / '.cache')
