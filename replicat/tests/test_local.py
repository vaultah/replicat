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

    local_backend.delete(file)
    # No longer visible
    assert list(local_backend.list_files()) == []

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


def test_exists(local_backend):
    file = 'a'
    assert not local_backend.exists(file)
    local_backend.upload(file, b'')
    assert local_backend.exists(file)


def test_clean(local_backend):
    (local_backend.path / 'A/B/C/D').mkdir(parents=True)
    (local_backend.path / 'A/B/C/D/somefile').touch()
    (local_backend.path / 'A/B/C/E').mkdir()

    (local_backend.path / 'A/B/K').mkdir()
    (local_backend.path / 'A/B/K/differentfile').touch()
    (local_backend.path / 'A/B/L').mkdir()
    (local_backend.path / 'A/B/M').mkdir()

    (local_backend.path / 'X').mkdir()
    (local_backend.path / 'Y').mkdir()
    (local_backend.path / 'Y/yetanotherfile').touch()

    before_deletion = set(local_backend.path.rglob('*'))

    local_backend.clean()

    assert before_deletion - set(local_backend.path.rglob('*')) == {
        local_backend.path / 'X',
        local_backend.path / 'A/B/M',
        local_backend.path / 'A/B/L',
        local_backend.path / 'A/B/C/E',
    }
