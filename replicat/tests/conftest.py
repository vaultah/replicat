import random

import pytest

from replicat.backends import local
from replicat.repository import Repository


@pytest.fixture
def local_backend(tmpdir):
    return local.Client(tmpdir / random.randbytes(4).hex())


@pytest.fixture
def local_repo(local_backend, tmpdir):
    return Repository(local_backend, concurrent=5, cache_directory=tmpdir / '.cache')
