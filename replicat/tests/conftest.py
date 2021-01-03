from types import SimpleNamespace

import pytest

from replicat.backends import local


@pytest.fixture
def local_backend(tmpdir):
    return local.Client(tmpdir)


@pytest.fixture
def args():
    return SimpleNamespace(concurrent=5, progress=False)
