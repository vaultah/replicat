import os
import re
import threading
import time
from unittest.mock import patch

import pytest

from replicat import exceptions, utils
from replicat.backends.local import Local
from replicat.repository import Repository


class TestInit:
    @pytest.mark.asyncio
    async def test_encrypted_no_password(self, local_backend):
        repo = Repository(local_backend, concurrent=1)
        with pytest.raises(exceptions.ReplicatError):
            # No password, and the "no encryption" flag was not set
            await repo.init()

    @pytest.mark.asyncio
    async def test_encrypted_ok(self, local_backend):
        repo = Repository(local_backend, concurrent=1)
        result = await repo.init(
            password=b'<password>',
            settings={'encryption.kdf.n': 4, 'chunking.min_length': 12_345},
        )

        assert local_backend.download('config') == repo.serialize(result.config)
        assert result.config == {
            'chunking': {
                'name': 'gclmulchunker',
                'min_length': 12_345,
                'max_length': 5_120_000,
            },
            'hashing': {'name': 'blake2b', 'length': 64},
            'encryption': {
                'cipher': {'name': 'aes_gcm', 'key_bits': 256, 'nonce_bits': 96}
            },
        }

        assert result.key.keys() == {'kdf', 'key_derivation_params', 'encrypted'}
        assert result.key['kdf'] == {
            'name': 'scrypt',
            'n': 4,
            'r': 8,
            'p': 1,
            'length': 32,
        }
        assert isinstance(result.key['key_derivation_params'], bytes)
        assert len(result.key['key_derivation_params']) == 32

        cipher, _ = utils.adapter_from_config(**result.config['encryption']['cipher'])
        kdf, _ = utils.adapter_from_config(**result.key['kdf'])
        private = repo.deserialize(
            cipher.decrypt(
                result.key['encrypted'],
                kdf.derive(b'<password>', params=result.key['key_derivation_params']),
            )
        )
        assert private['mac'] == {'name': 'blake2b', 'length': 64}
        assert private['shared_kdf'] == {'name': 'blake2b', 'length': 32}
        assert isinstance(private['shared_encryption_secret'], bytes)
        assert len(private['shared_encryption_secret']) == 64
        assert isinstance(private['mac_key'], bytes)
        assert len(private['mac_key']) == 64
        assert isinstance(private['chunker_secret'], bytes)
        assert len(private['chunker_secret']) == 16

    @pytest.mark.asyncio
    async def test_unencrypted_ok(self, local_backend):
        repo = Repository(local_backend, concurrent=1)
        result = await repo.init(
            password=b'<password>',
            settings={'encryption': None, 'chunking.max_length': 128_129},
        )

        assert local_backend.download('config') == repo.serialize(result.config)
        assert result.config == {
            'chunking': {
                'name': 'gclmulchunker',
                'min_length': 128_000,
                'max_length': 128_129,
            },
            'hashing': {'name': 'blake2b', 'length': 64},
        }
        assert result.key is None


class TestEncryptedUnlock:
    @pytest.fixture
    async def init_params(self, local_backend):
        return await Repository(local_backend, concurrent=1).init(
            password=b'<password>', settings={'encryption.kdf.n': 4}
        )

    @pytest.mark.asyncio
    async def test_no_password(self, local_backend, init_params):
        repo = Repository(local_backend, concurrent=1)
        with pytest.raises(exceptions.ReplicatError):
            await repo.unlock(key=init_params.key)

    @pytest.mark.asyncio
    async def test_no_key(self, local_backend, init_params):
        repo = Repository(local_backend, concurrent=1)
        with pytest.raises(exceptions.ReplicatError):
            await repo.unlock(password=b'<password>')

    @pytest.mark.asyncio
    async def test_bad_password(self, local_backend, init_params):
        repo = Repository(local_backend, concurrent=1)
        with pytest.raises(exceptions.ReplicatError):
            await repo.unlock(password=b'<no-pass word>', key=init_params.key)

    @pytest.mark.asyncio
    async def test_ok(self, local_backend, init_params):
        repo = Repository(local_backend, concurrent=1)
        await repo.unlock(password=b'<password>', key=init_params.key)
        assert repo.properties.encrypted


class TestUnencryptedUnlock:
    @pytest.fixture
    async def init_params(self, local_backend):
        return await Repository(local_backend, concurrent=1).init(
            settings={'encryption': None}
        )

    @pytest.mark.asyncio
    async def test_ok(self, local_backend, init_params):
        repo = Repository(local_backend, concurrent=1)
        await repo.unlock()
        assert not repo.properties.encrypted


class TestSnapshot:
    @pytest.fixture
    def source_files(self, tmp_path):
        rv = []
        sizes = {
            "a": 4096,
            "b": 2048,
            "c": 1024,
            "d": 512,
            "e": 256,
            "f": 128,
            "g": 64,
            "h": 32,
            'i': 16,
            'j': 8,
            'k': 4,
            'l': 2,
            'm': 0,
            'n': 0,
        }

        for name, size in sizes.items():
            file = tmp_path / name
            file.write_bytes(os.urandom(size))
            rv.append(file)

        return rv

    @pytest.mark.asyncio
    async def test_encrypted_data(self, local_backend, source_files):
        repo = Repository(backend=local_backend, concurrent=5)
        await repo.init(
            password=b'<password>',
            settings={
                'encryption.kdf.n': 4,
                'chunking.min_length': 256,
                'chunking.max_length': 512,
            },
        )
        result = await repo.snapshot(paths=source_files)

        snapshots = list(local_backend.list_files('snapshots'))
        assert len(snapshots) == 1

        snapshot_location = repo.snapshot_name_to_location(result.name)
        assert snapshots[0] == snapshot_location
        assert repo.properties.decrypt(
            local_backend.download(snapshot_location), repo.properties.userkey,
        ) == repo.serialize(result.data)

        # Small files come first
        source_files.reverse()
        snapshot_files = sorted(
            result.data['files'], key=lambda x: x['name'], reverse=True
        )
        assert len(source_files) == len(snapshot_files)

        restored_files = []
        for file, snapshot_data in zip(source_files, snapshot_files):
            contents = b''

            for chunk in sorted(snapshot_data['chunks'], key=lambda x: x['counter']):
                chunk_location = repo.chunk_name_to_location(chunk['name'])
                chunk_bytes = repo.properties.decrypt(
                    local_backend.download(chunk_location),
                    repo.properties.derive_shared_key(bytes.fromhex(chunk['digest'])),
                )
                contents += chunk_bytes[chunk['start'] : chunk['end']]

            restored_files.append(contents)

        assert all(x.read_bytes() == y for x, y in zip(source_files, restored_files))

    @pytest.mark.asyncio
    async def test_unencrypted_data(self, local_backend, tmp_path, source_files):
        repo = Repository(backend=local_backend, concurrent=5)
        await repo.init(
            settings={
                'encryption': None,
                'chunking.min_length': 256,
                'chunking.max_length': 512,
            }
        )
        result = await repo.snapshot(paths=source_files)

        snapshots = list(local_backend.list_files('snapshots'))
        assert len(snapshots) == 1

        snapshot_location = repo.snapshot_name_to_location(result.name)
        assert snapshots[0] == snapshot_location
        assert local_backend.download(snapshot_location) == repo.serialize(result.data)

        # Small files come first
        source_files.reverse()
        snapshot_files = sorted(
            result.data['files'], key=lambda x: x['name'], reverse=True
        )
        assert len(source_files) == len(snapshot_files)

        restored_files = []
        for file, snapshot_data in zip(source_files, snapshot_files):
            contents = b''

            for chunk in sorted(snapshot_data['chunks'], key=lambda x: x['counter']):
                chunk_location = repo.chunk_name_to_location(chunk['name'])
                chunk_bytes = local_backend.download(chunk_location)
                contents += chunk_bytes[chunk['start'] : chunk['end']]

            restored_files.append(contents)

        assert all(x.read_bytes() == y for x, y in zip(source_files, restored_files))

    @pytest.mark.asyncio
    async def test_encrypted_deduplicated_references(self, local_backend, tmp_path):
        repo = Repository(backend=local_backend, concurrent=5)
        await repo.init(
            password=b'<password>',
            settings={
                'encryption.kdf.n': 4,
                'chunking.min_length': 256,
                'chunking.max_length': 512,
            },
        )

        contents = os.urandom(4) * 1024
        file = tmp_path / 'file'
        file.write_bytes(contents)
        result = await repo.snapshot(paths=[file])

        assert len(result.data['files']) == 1

        chunks = result.data['files'][0]['chunks']
        assert len(chunks) == 16
        assert len({x['name'] for x in chunks}) == 1

        chunk_location = repo.chunk_name_to_location(chunks[0]['name'])
        shared_key = repo.properties.derive_shared_key(
            bytes.fromhex(chunks[0]['digest'])
        )
        decrypted = repo.properties.decrypt(
            local_backend.download(chunk_location), shared_key
        )
        assert decrypted * 16 == contents

    @pytest.mark.asyncio
    async def test_unencrypted_deduplicated_references(self, local_backend, tmp_path):
        repo = Repository(backend=local_backend, concurrent=5)
        await repo.init(
            settings={
                'encryption': None,
                'chunking.min_length': 256,
                'chunking.max_length': 512,
            }
        )
        contents = os.urandom(4) * 1024
        file = tmp_path / 'file'
        file.write_bytes(contents)
        result = await repo.snapshot(paths=[file])

        assert len(result.data['files']) == 1

        chunks = result.data['files'][0]['chunks']
        assert len(chunks) == 16
        assert len({x['name'] for x in chunks}) == 1

        chunk_location = repo.chunk_name_to_location(chunks[0]['name'])
        assert local_backend.download(chunk_location) * 16 == contents

    @pytest.mark.asyncio
    async def test_backend_error_propagation(self, local_backend, tmp_path):
        repo = Repository(backend=local_backend, concurrent=5)
        await repo.init(
            settings={
                'encryption': None,
                'chunking.min_length': 256,
                'chunking.max_length': 512,
            }
        )

        file = tmp_path / 'file'
        file.write_bytes(os.urandom(1_024))

        class _TestException(Exception):
            pass

        with patch.object(local_backend, 'upload', side_effect=_TestException()):
            with pytest.raises(_TestException):
                await repo.snapshot(paths=[file])

        assert list(local_backend.list_files('snapshots')) == []

    @pytest.mark.asyncio
    async def test_wait_for_chunk_upload(self, local_backend, tmp_path):
        repo = Repository(backend=local_backend, concurrent=5)
        await repo.init(
            settings={
                'encryption': None,
                'chunking.min_length': 256,
                'chunking.max_length': 512,
            }
        )

        data = os.urandom(1_024)
        file = tmp_path / 'file'
        file.write_bytes(data)

        upload_lock = threading.Lock()
        bytes_remaining = len(data)

        def upld(name, contents):
            nonlocal bytes_remaining
            with upload_lock:
                bytes_remaining -= len(contents)

            rv = Local.upload(local_backend, name, contents)
            if not bytes_remaining and not name.startswith('snapshots/'):
                # Simulate work
                time.sleep(0.5)

            return rv

        with patch.object(local_backend, 'upload', side_effect=upld) as upload_mock:
            result = await repo.snapshot(paths=[file])

        snapshots = list(local_backend.list_files('snapshots/'))
        chunks = list(local_backend.list_files('data/'))
        assert len(snapshots) == 1
        assert len(chunks) > 0
        assert len(snapshots) + len(chunks) == upload_mock.call_count
        assert len(result.data['files'][0]['chunks']) == len(chunks)


class TestRestore:
    @pytest.mark.asyncio
    async def test_encrypted_data(self, local_backend, tmp_path):
        repo = Repository(backend=local_backend, concurrent=5)
        await repo.init(
            password=b'<password>',
            settings={
                'encryption.kdf.n': 4,
                'chunking.min_length': 256,
                'chunking.max_length': 512,
            },
        )

        first_data = os.urandom(4_096)
        first_file = tmp_path / 'first_file'
        first_file.write_bytes(first_data)

        second_data = os.urandom(4_096)
        second_file = tmp_path / 'directory/second_directory/second_file'
        second_file.parent.mkdir(exist_ok=True, parents=True)
        second_file.write_bytes(second_data)

        snapshot_params = await repo.snapshot(paths=[first_file, second_file])
        result = await repo.restore(snapshot_regex=snapshot_params.name, path=tmp_path)
        assert set(result.files) == {str(first_file), str(second_file)}
        assert tmp_path.joinpath(*first_file.parts[1:]).read_bytes() == first_data
        assert tmp_path.joinpath(*second_file.parts[1:]).read_bytes() == second_data

    @pytest.mark.asyncio
    async def test_unencrypted_data(self, local_backend, tmp_path):
        repo = Repository(backend=local_backend, concurrent=5)
        await repo.init(
            settings={
                'encryption': None,
                'chunking.min_length': 256,
                'chunking.max_length': 512,
            },
        )

        first_data = os.urandom(4_096)
        first_file = tmp_path / 'first_file'
        first_file.write_bytes(first_data)

        second_data = os.urandom(4_096)
        second_file = tmp_path / 'directory/second_directory/second_file'
        second_file.parent.mkdir(exist_ok=True, parents=True)
        second_file.write_bytes(second_data)

        await repo.snapshot(paths=[first_file, second_file])
        result = await repo.restore(path=tmp_path)
        assert set(result.files) == {str(first_file), str(second_file)}
        assert tmp_path.joinpath(*first_file.parts[1:]).read_bytes() == first_data
        assert tmp_path.joinpath(*second_file.parts[1:]).read_bytes() == second_data

    @pytest.mark.asyncio
    async def test_defaults_to_latest_file_version(self, local_backend, tmp_path):
        repo = Repository(backend=local_backend, concurrent=5)
        await repo.init(
            settings={
                'encryption': None,
                'chunking.min_length': 256,
                'chunking.max_length': 512,
            },
        )

        file = tmp_path / 'file'
        file.write_bytes(os.urandom(4_096))
        await repo.snapshot(paths=[file])

        second_version = os.urandom(4_096)
        file.write_bytes(second_version)
        await repo.snapshot(paths=[file])

        result = await repo.restore(files_regex=re.escape(str(file)), path=tmp_path)
        assert result.files == [str(file)]
        assert tmp_path.joinpath(*file.parts[1:]).read_bytes() == second_version

    @pytest.mark.asyncio
    async def test_snapshot_version(self, local_backend, tmp_path):
        repo = Repository(backend=local_backend, concurrent=5)
        await repo.init(
            settings={
                'encryption': None,
                'chunking.min_length': 256,
                'chunking.max_length': 512,
            },
        )

        file = tmp_path / 'file'
        first_version = os.urandom(4_096)
        file.write_bytes(first_version)
        first_snapshot = await repo.snapshot(paths=[file])

        file.write_bytes(os.urandom(4_096))
        await repo.snapshot(paths=[file])

        result = await repo.restore(snapshot_regex=first_snapshot.name, path=tmp_path)
        assert result.files == [str(file)]
        assert tmp_path.joinpath(*file.parts[1:]).read_bytes() == first_version
