import os
import time
from unittest.mock import patch

import pytest

from replicat import exceptions
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

        with patch.object(local_backend, 'upload') as upload_mock:
            result = await repo.init(
                password=b'<password>', settings={'encryption.kdf.n': 4}
            )

        upload_mock.assert_called_once_with('config', repo.serialize(result.config))
        assert result.key is not None
        assert result.key.keys() == {
            'encrypted',
            'kdf',
            'key_derivation_params',
        }
        assert result.config.keys() == {'chunking', 'hashing', 'encryption'}

    @pytest.mark.asyncio
    async def test_unencrypted_ok(self, local_backend):
        repo = Repository(local_backend, concurrent=1)

        with patch.object(local_backend, 'upload') as upload_mock:
            result = await repo.init(
                password=b'<password>', settings={'encryption': None}
            )

        upload_mock.assert_called_once_with('config', repo.serialize(result.config))
        assert result.key is None
        assert result.config.keys() == {'chunking', 'hashing'}


class TestUnlock:
    @pytest.mark.asyncio
    async def test_no_password(self, local_backend):
        params = await Repository(local_backend, concurrent=1).init(
            password=b'<password>', settings={'encryption.kdf.n': 4}
        )
        repo = Repository(local_backend, concurrent=1)
        with pytest.raises(exceptions.ReplicatError):
            await repo.unlock(key=params.key)

    @pytest.mark.asyncio
    async def test_no_key(self, local_backend):
        await Repository(local_backend, concurrent=1).init(
            password=b'<password>', settings={'encryption.kdf.n': 4}
        )
        repo = Repository(local_backend, concurrent=1)
        with pytest.raises(exceptions.ReplicatError):
            await repo.unlock(password=b'<password>')

    @pytest.mark.asyncio
    async def test_bad_password(self, local_backend):
        params = await Repository(local_backend, concurrent=1).init(
            password=b'<password>', settings={'encryption.kdf.n': 4}
        )
        repo = Repository(local_backend, concurrent=1)

        with pytest.raises(exceptions.ReplicatError):
            await repo.unlock(password=b'<not password>', key=params.key)

    @pytest.mark.asyncio
    async def test_ok(self, local_backend):
        params = await Repository(local_backend, concurrent=1).init(
            password=b'<password>', settings={'encryption.kdf.n': 4}
        )
        repo = Repository(local_backend, concurrent=1)
        await repo.unlock(password=b'<password>', key=params.key)


class TestSnapshotEncrypted:
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
        params = await repo.init(
            password=b'<password>',
            settings={
                'encryption.kdf.n': 4,
                'chunking.min_length': 256,
                'chunking.max_length': 512,
            },
        )
        await repo.unlock(password=b'<password>', key=params.key)
        result = await repo.snapshot(paths=source_files)
        assert len([*local_backend.list_files('snapshots')]) == 1
        assert len([*local_backend.list_files(f'snapshots/{result.snapshot}')]) == 1

        # Small files come first
        source_files.reverse()
        snapshot_files = sorted(
            result.data['files'], key=lambda x: x['name'], reverse=True
        )
        assert len(source_files) == len(snapshot_files)

        restored_files = []
        for file, snapshot_data in zip(source_files, snapshot_files):
            file_snapshot = b''

            for chunk in sorted(snapshot_data['chunks'], key=lambda x: x['counter']):
                chunk_name = chunk['name']
                (chunk_path,) = local_backend.list_files(
                    f'data/{chunk_name[:2]}/{chunk_name}'
                )
                shared_key = repo.properties.derive_shared_key(
                    bytes.fromhex(chunk['digest'])
                )
                decrypted_chunk = repo.properties.decrypt(
                    (local_backend.path / chunk_path).read_bytes(), shared_key
                )
                file_snapshot += decrypted_chunk[chunk['start'] : chunk['end']]

            restored_files.append(file_snapshot)

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
        assert len([*local_backend.list_files('snapshots')]) == 1
        assert len([*local_backend.list_files(f'snapshots/{result.snapshot}')]) == 1

        # Small files come first
        source_files.reverse()
        snapshot_files = sorted(
            result.data['files'], key=lambda x: x['name'], reverse=True
        )
        assert len(source_files) == len(snapshot_files)

        restored_files = []
        for file, snapshot_data in zip(source_files, snapshot_files):
            file_snapshot = b''

            for chunk in sorted(snapshot_data['chunks'], key=lambda x: x['counter']):
                chunk_name = chunk['name']
                (chunk_path,) = local_backend.list_files(
                    f'data/{chunk_name[:2]}/{chunk_name}'
                )
                contents = (local_backend.path / chunk_path).read_bytes()
                file_snapshot += contents[chunk['start'] : chunk['end']]

            restored_files.append(file_snapshot)

        assert all(x.read_bytes() == y for x, y in zip(source_files, restored_files))

    @pytest.mark.asyncio
    async def test_encrypted_deduplicated_references(self, local_backend, tmp_path):
        repo = Repository(backend=local_backend, concurrent=5)
        params = await repo.init(
            password=b'<password>',
            settings={
                'encryption.kdf.n': 4,
                'chunking.min_length': 256,
                'chunking.max_length': 512,
            },
        )
        await repo.unlock(password=b'<password>', key=params.key)
        contents = os.urandom(4) * 1024
        file = tmp_path / 'file'
        file.write_bytes(contents)

        result = await repo.snapshot(paths=[file])
        assert len(result.data['files']) == 1

        referenced = [x['digest'] for x in result.data['files'][0]['chunks']]
        assert len(referenced) == 16
        assert len(set(referenced)) == 1

        chunks = list(local_backend.list_files('data'))
        assert len(chunks) == 1
        shared_key = repo.properties.derive_shared_key(bytes.fromhex(referenced[0]))
        decrypted = repo.properties.decrypt(
            (local_backend.path / chunks[0]).read_bytes(), shared_key
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

        referenced = [x['digest'] for x in result.data['files'][0]['chunks']]
        assert len(referenced) == 16
        assert len(set(referenced)) == 1

        chunks = list(local_backend.list_files('data'))
        assert len(chunks) == 1
        stored = (local_backend.path / chunks[0]).read_bytes()
        assert stored * 16 == contents

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

        assert len([*local_backend.list_files('snapshots')]) == 0

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

        file = tmp_path / 'file'
        file.write_bytes(os.urandom(1_024))

        def upld(name, contents):
            if not name.startswith('snapshots/'):
                time.sleep(1)

            return Local.upload(local_backend, name, contents)

        with patch.object(local_backend, 'upload', side_effect=upld) as upload_mock:
            result = await repo.snapshot(paths=[file])

        snapshots = list(local_backend.list_files('snapshots'))
        chunks = list(local_backend.list_files('data'))
        assert len(snapshots) == 1
        assert len(chunks) > 0
        assert len(snapshots) + len(chunks) == upload_mock.call_count
        assert len(result.data['files'][0]['chunks']) == len(chunks)
