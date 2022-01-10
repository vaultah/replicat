import pytest

from replicat.backends import local
from replicat.repository import Repository


@pytest.fixture
def local_backend(tmpdir):
    return local.Client(tmpdir)


@pytest.fixture
def local_repo(local_backend):
    return Repository(local_backend, concurrent=5)
