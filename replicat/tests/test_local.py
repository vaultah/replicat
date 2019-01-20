import asyncio
import pytest
from replicat.backends import local


def test_list_hide(local_backend):
    assert list(local_backend.list_files()) == []

    file = 'abc/def/ghi'
    local_backend.upload(file, b'')
    # All these should find exactly one file
    assert list(local_backend.list_files()) == [file]
    assert list(local_backend.list_files('')) == [file]
    assert list(local_backend.list_files('a')) == [file]
    assert list(local_backend.list_files('abc')) == [file]
    assert list(local_backend.list_files('abc/def')) == [file]
    assert list(local_backend.list_files('abc/def/')) == [file]
    assert list(local_backend.list_files('abc/def/g')) == [file]
    assert list(local_backend.list_files('abc/def/gh')) == [file]
    assert list(local_backend.list_files('abc/def/ghi')) == [file]
    # ... except this one ("not a directory")
    assert list(local_backend.list_files('abc/def/ghi/')) == []

    local_backend.hide_file(file)
    # We should see it anyway
    assert list(local_backend.list_files()) == [file + '_']

    dotfile = 'jkl/.mno'
    local_backend.upload(dotfile, b'')
    # We should still see it, even if glob wouldn't
    assert list(local_backend.list_files('jkl')) == [dotfile]


def test_upload_download(local_backend):
    file = 'a'
    local_backend.upload(file, b'<stuff>')
    # All temporary files were deleted
    assert list(local_backend.list_files()) == [file]
    # A real file was created
    assert (local_backend.path / file).exists()
    # ... and its contents are as expected
    assert local_backend.download(file) == b'<stuff>'
