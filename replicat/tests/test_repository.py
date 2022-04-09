import asyncio
import os
import re
import threading
import time
from itertools import islice
from random import Random
from unittest.mock import ANY, DEFAULT, AsyncMock, call, patch

import pytest

from replicat import exceptions, utils
from replicat.backends.local import Local
from replicat.repository import LockTypes, Repository
from replicat.utils import adapters


class TestHelperMethods:
    def test_get_chunk_location(self, local_repo):
        location = local_repo.get_chunk_location(
            name='GHIJKLMNOPQR', tag='0123456789ABCDEF'
        )
        assert location == local_repo.CHUNK_PREFIX + '01/23/456789ABCDEF-GHIJKLMNOPQR'

    def test_parse_chunk_location(self, local_repo):
        location = local_repo.CHUNK_PREFIX + '01/23/456789ABCDEF-GHIJKLMNOPQR'
        name, tag = local_repo.parse_chunk_location(location)
        assert name == 'GHIJKLMNOPQR'
        assert tag == '0123456789ABCDEF'

    def test_get_snapshot_location(self, local_repo):
        location = local_repo.get_snapshot_location(
            name='GHIJKLMNOPQR', tag='0123456789ABCDEF'
        )
        assert location == local_repo.SNAPSHOT_PREFIX + '01/23456789ABCDEF-GHIJKLMNOPQR'

    def test_parse_snapshot_location(self, local_repo):
        location = local_repo.SNAPSHOT_PREFIX + '01/23456789ABCDEF-GHIJKLMNOPQR'
        name, tag = local_repo.parse_snapshot_location(location)
        assert name == 'GHIJKLMNOPQR'
        assert tag == '0123456789ABCDEF'

    def test_get_lock_location(self, local_repo):
        location = local_repo.get_lock_location(name='a-b-c-d-e', tag='012345678')
        assert location == local_repo.LOCK_PREFIX + 'a-b-c-d-e-012345678'

    def test_parse_lock_location(self, local_repo):
        location = local_repo.LOCK_PREFIX + 'a-b-c-d-e-012345678'
        name, tag = local_repo.parse_lock_location(location)
        assert name == 'a-b-c-d-e'
        assert tag == '012345678'

    @pytest.mark.parametrize(
        'ts, start, end',
        [
            (0, 0, Repository.LOCK_TTL),
            (Repository.LOCK_TTL - 1, 0, Repository.LOCK_TTL),
            (Repository.LOCK_TTL, Repository.LOCK_TTL, Repository.LOCK_TTL * 2),
            (Repository.LOCK_TTL + 1, Repository.LOCK_TTL, Repository.LOCK_TTL * 2),
            (Repository.LOCK_TTL * 2 - 1, Repository.LOCK_TTL, Repository.LOCK_TTL * 2),
        ],
    )
    def test_get_lock_frame(self, local_repo, ts, start, end):
        assert local_repo.get_lock_frame(ts) == (start, end)

    @pytest.mark.parametrize(
        'tss, lock_ttl, lock_ttp, values',
        [
            ([123, 187, 188, 189], 10, 1, [120, 180, 180, 190]),
            ([125, 127, 127, 127], 10, 3, [120, 130, 130, 130]),
            ([123, 188, 188, 188, 188], 10, 2, [120, 190, 190, 190, 190]),
            ([100, 109, 2_198, 2_199, 2_200], 1_000, 1, [0, 0, 2_000, 2_000, 2_000]),
            ([39, 39], 20, 0, [20, 20]),
            ([39, 39], 20, 1, [20, 40]),
            ([39, 100], 100, 0, [0, 100]),
        ],
    )
    def test_lock_frames(self, local_backend, tss, lock_ttl, lock_ttp, values):
        class _repository(Repository):
            LOCK_TTL = lock_ttl
            LOCK_TTP = lock_ttp

        repository = _repository(local_backend, concurrent=5)
        it = iter(tss)

        with patch.object(utils, 'utc_timestamp', side_effect=lambda: next(it)):
            frames_it = repository.lock_frames(next(it))
            generated = list(islice(frames_it, len(values)))

        assert generated == values


class TestLockWorker:
    @pytest.mark.parametrize('lock_type', LockTypes)
    @pytest.mark.asyncio
    async def test_exclusive(self, local_backend, tmp_path, lock_type):
        repository = Repository(local_backend, concurrent=5, exclusive=True)
        await repository.init(
            password=b'<password>', settings={'encryption': {'kdf': {'n': 4}}}
        )
        with patch.object(local_backend, 'upload') as upload_mock, patch.object(
            local_backend, 'delete'
        ) as delete_mock:
            await repository.lock_worker(12_345, LockTypes.create_read)
            upload_mock.assert_not_called()
            delete_mock.assert_not_called()

    @pytest.mark.parametrize('lock_type', LockTypes)
    @pytest.mark.asyncio
    async def test_not_exclusive(self, local_backend, tmp_path, lock_type):
        repository = Repository(local_backend, concurrent=5)
        await repository.init(
            password=b'<password>', settings={'encryption': {'kdf': {'n': 4}}}
        )

        with patch.object(local_backend, 'upload') as upload_mock, patch.object(
            local_backend, 'delete'
        ) as delete_mock, patch.object(
            repository,
            'lock_frames',
            return_value=[19, 19, 23, 29, 29, 29, 31, 37, 37, 41, 43, 47],
        ) as timestamp_mock:
            await repository.lock_worker(19, lock_type, delay=0)

        unique_tss = sorted(set(timestamp_mock.return_value))
        assert upload_mock.call_count == len(unique_tss)
        lock_locations = [
            repository._lock_ts_to_location(x, lock_type) for x in unique_tss
        ]
        upload_mock.assert_has_calls([call(x, b'') for x in lock_locations])

        assert delete_mock.call_count == len(unique_tss)
        delete_mock.assert_has_calls([call(x) for x in lock_locations], any_order=True)


class TestWaitForLock:
    @pytest.mark.parametrize('lock_type', LockTypes)
    @pytest.mark.asyncio
    async def test_exclusive(self, local_backend, tmp_path, lock_type):
        repository = Repository(local_backend, concurrent=5, exclusive=True)
        await repository.init(
            password=b'<password>', settings={'encryption': {'kdf': {'n': 4}}}
        )
        with patch.object(local_backend, 'exists') as exists_mock, patch.object(
            asyncio, 'sleep'
        ) as sleep_mock:
            await repository.wait_for_lock(1, lock_type)
            sleep_mock.assert_not_awaited()
            exists_mock.assert_not_called()

    @pytest.mark.parametrize('lock_type', LockTypes)
    @pytest.mark.parametrize('wait_time', [-11, 0, 7])
    @pytest.mark.asyncio
    async def test_exists(self, local_backend, tmp_path, lock_type, wait_time):
        repository = Repository(local_backend, concurrent=5)
        await repository.init(
            password=b'<password>', settings={'encryption': {'kdf': {'n': 4}}}
        )
        with patch.object(
            local_backend, 'exists', return_value=True
        ) as exists_mock, patch.object(utils, 'utc_timestamp') as ts_mock, patch.object(
            repository,
            'get_lock_frame',
            return_value=(787, 997),
        ) as frame_mock, patch.object(
            asyncio, 'sleep'
        ) as sleep_mock:
            with pytest.raises(exceptions.Locked):
                await repository.wait_for_lock(wait_time, lock_type)

            sleep_mock.assert_awaited_once_with(wait_time)
            frame_mock.assert_called_once_with(ts_mock.return_value)
            exists_mock.assert_called_once_with(
                repository._lock_ts_to_location(frame_mock.return_value[0], lock_type)
            )

    @pytest.mark.parametrize('lock_type', LockTypes)
    @pytest.mark.parametrize('wait_time', [-11, 0, 7])
    @pytest.mark.asyncio
    async def test_does_not_exist(self, local_backend, tmp_path, lock_type, wait_time):
        repository = Repository(local_backend, concurrent=5)
        await repository.init(
            password=b'<password>', settings={'encryption': {'kdf': {'n': 4}}}
        )
        with patch.object(
            local_backend, 'exists', return_value=False
        ) as exists_mock, patch.object(utils, 'utc_timestamp') as ts_mock, patch.object(
            repository,
            'get_lock_frame',
            return_value=(787, 997),
        ) as frame_mock, patch.object(
            asyncio, 'sleep'
        ) as sleep_mock:
            await repository.wait_for_lock(wait_time, lock_type)

            sleep_mock.assert_awaited_once_with(wait_time)
            frame_mock.assert_called_once_with(ts_mock.return_value)
            exists_mock.assert_called_once_with(
                repository._lock_ts_to_location(frame_mock.return_value[0], lock_type)
            )


class TestInit:
    @pytest.mark.asyncio
    async def test_encrypted_no_password(self, local_repo):
        with pytest.raises(exceptions.ReplicatError):
            # No password, and the "no encryption" flag was not set
            await local_repo.init()

    @pytest.mark.asyncio
    async def test_encrypted_ok(self, local_backend, local_repo, tmp_path):
        result = await local_repo.init(
            password=b'<password>',
            settings={
                'chunking': {'min_length': 12_345},
                'encryption': {'kdf': {'n': 4}},
            },
            key_output_path=tmp_path / 'output.key',
        )
        # Config contents and defaults
        assert local_backend.download('config') == local_repo.serialize(result.config)
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

        # Key contents and defaults
        assert (tmp_path / 'output.key').read_bytes() == local_repo.serialize(
            result.key
        )
        assert result.key.keys() == {'kdf', 'kdf_params', 'private'}
        assert result.key['kdf'] == {
            'name': 'scrypt',
            'n': 4,
            'r': 8,
            'p': 1,
            'length': 32,
        }
        assert isinstance(result.key['kdf_params'], bytes)
        assert len(result.key['kdf_params']) == 32
        assert isinstance(result.key['private'], bytes)

        cipher = adapters.aes_gcm(key_bits=256, nonce_bits=96)
        kdf = adapters.scrypt(r=8, n=4, p=1, length=32)
        userkey = kdf.derive(b'<password>', params=result.key['kdf_params'])

        private = local_repo.deserialize(
            cipher.decrypt(
                result.key['private'],
                userkey,
            )
        )
        assert private['mac'] == {'name': 'blake2b', 'length': 64}
        assert private['shared_kdf'] == {'name': 'blake2b', 'length': 32}
        assert isinstance(private['shared_key'], bytes)
        assert len(private['shared_key']) == 32
        assert isinstance(private['shared_kdf_params'], bytes)
        assert len(private['shared_kdf_params']) == 16
        assert isinstance(private['mac_params'], bytes)
        assert len(private['mac_params']) == 64
        assert isinstance(private['chunker_params'], bytes)
        assert len(private['chunker_params']) == 16
        assert local_repo.props.userkey == userkey
        assert local_repo.props.private == private
        assert local_repo.props.encrypted

    @pytest.mark.asyncio
    async def test_unencrypted_ok(self, local_backend, local_repo):
        result = await local_repo.init(
            password=b'<password>',
            settings={'encryption': None, 'chunking': {'max_length': 128_129}},
        )

        assert local_backend.download('config') == local_repo.serialize(result.config)
        assert result.config == {
            'chunking': {
                'name': 'gclmulchunker',
                'min_length': 128_000,
                'max_length': 128_129,
            },
            'hashing': {'name': 'blake2b', 'length': 64},
        }
        assert result.key is None
        assert not local_repo.props.encrypted


class TestEncryptedUnlock:
    @pytest.fixture(autouse=True)
    async def init_params(self, local_repo):
        return await local_repo.init(
            password=b'<password>', settings={'encryption': {'kdf': {'n': 4}}}
        )

    @pytest.mark.asyncio
    async def test_no_password(self, local_repo, init_params):
        with pytest.raises(exceptions.ReplicatError):
            await local_repo.unlock(key=init_params.key)

    @pytest.mark.asyncio
    async def test_no_key(self, local_repo):
        with pytest.raises(exceptions.ReplicatError):
            await local_repo.unlock(password=b'<password>')

    @pytest.mark.asyncio
    async def test_bad_password(self, local_repo, init_params):
        with pytest.raises(exceptions.DecryptionError):
            await local_repo.unlock(password=b'<no-pass word>', key=init_params.key)

    @pytest.mark.asyncio
    async def test_ok(self, local_repo, init_params):
        await local_repo.unlock(password=b'<password>', key=init_params.key)

        cipher = adapters.aes_gcm(key_bits=256, nonce_bits=96)
        kdf = adapters.scrypt(r=8, n=4, p=1, length=32)
        userkey = kdf.derive(b'<password>', params=init_params.key['kdf_params'])
        private = local_repo.deserialize(
            cipher.decrypt(init_params.key['private'], userkey)
        )

        assert local_repo.props.userkey == userkey
        assert local_repo.props.private == private
        assert local_repo.props.encrypted


class TestUnencryptedUnlock:
    @pytest.fixture
    async def init_params(self, local_repo):
        return await local_repo.init(settings={'encryption': None})

    @pytest.mark.asyncio
    async def test_ok(self, local_repo, init_params):
        await local_repo.unlock()
        assert not local_repo.props.encrypted


class TestAddKey:
    @pytest.mark.asyncio
    async def test_unencrypted_repository(self, local_repo):
        await local_repo.init(settings={'encryption': None})
        with pytest.raises(exceptions.ReplicatError):
            await local_repo.add_key(password=b'<password>')

    @pytest.mark.asyncio
    async def test_encrypted_repository_shared_key(self, local_repo, tmp_path):
        await local_repo.init(
            password=b'<password>', settings={'encryption': {'kdf': {'n': 4}}}
        )
        result = await local_repo.add_key(
            password=b'<different password>',
            settings={
                'encryption': {
                    'kdf': {'n': 8, 'r': 4},
                },
            },
            shared=True,
            key_output_path=tmp_path / 'output.key',
        )

        assert (tmp_path / 'output.key').read_bytes() == local_repo.serialize(
            result.new_key
        )
        assert result.new_key.keys() == {'kdf', 'kdf_params', 'private'}
        assert result.new_key['kdf'] == {
            'name': 'scrypt',
            'n': 8,
            'r': 4,
            'p': 1,
            'length': 32,
        }
        assert isinstance(result.new_key['kdf_params'], bytes)
        assert len(result.new_key['kdf_params']) == 32

        props_before = local_repo.props
        await local_repo.unlock(password=b'<different password>', key=result.new_key)
        assert local_repo.props is not props_before
        assert local_repo.props.private == props_before.private

    @pytest.mark.asyncio
    async def test_encrypted_repository_independent_key(self, local_repo, tmp_path):
        await local_repo.init(
            password=b'<password>', settings={'encryption': {'kdf': {'n': 4}}}
        )
        props_before = local_repo.props

        result = await local_repo.add_key(
            password=b'<different password>',
            settings={
                'encryption': {
                    'kdf': {'n': 8, 'r': 4},
                },
            },
            shared=False,
            key_output_path=tmp_path / 'output.key',
        )
        assert (tmp_path / 'output.key').read_bytes() == local_repo.serialize(
            result.new_key
        )
        assert result.new_key.keys() == {'kdf', 'kdf_params', 'private'}
        assert result.new_key['kdf'] == {
            'name': 'scrypt',
            'n': 8,
            'r': 4,
            'p': 1,
            'length': 32,
        }
        assert isinstance(result.new_key['kdf_params'], bytes)
        assert len(result.new_key['kdf_params']) == 32

        await local_repo.unlock(password=b'<different password>', key=result.new_key)
        assert local_repo.props is not props_before
        private_before = props_before.private
        private = local_repo.props.private
        assert private['mac'] == {'name': 'blake2b', 'length': 64}
        assert private['shared_kdf'] == {'name': 'blake2b', 'length': 32}
        assert isinstance(private['shared_key'], bytes)
        assert private['shared_key'] != private_before['shared_key']
        assert private['shared_kdf_params'] != private_before['shared_kdf_params']
        assert isinstance(private['shared_kdf_params'], bytes)
        assert len(private['shared_kdf_params']) == 16
        assert private['mac_params'] != private_before['mac_params']
        assert isinstance(private['mac_params'], bytes)
        assert len(private['mac_params']) == 64
        assert private['chunker_params'] != private_before['chunker_params']
        assert isinstance(private['chunker_params'], bytes)
        assert len(private['chunker_params']) == 16


class TestSnapshot:
    @pytest.mark.asyncio
    async def test_encrypted_data(self, local_backend, local_repo, tmp_path):
        await local_repo.init(
            password=b'<password>',
            settings={
                'encryption': {'kdf': {'n': 4}},
                'chunking': {
                    'min_length': 256,
                    'max_length': 512,
                },
            },
        )

        rnd = Random(0)
        file_contents = {
            tmp_path / 'a': rnd.randbytes(4099),
            tmp_path / 'b': rnd.randbytes(32),
            tmp_path / 'c': rnd.randbytes(1023),
            tmp_path / 'd': rnd.randbytes(517),
            tmp_path / 'e': rnd.randbytes(2),
            tmp_path / 'f': rnd.randbytes(128),
            tmp_path / 'g': rnd.randbytes(64),
            tmp_path / 'h': rnd.randbytes(2048),
            tmp_path / 'i': rnd.randbytes(19),
            tmp_path / 'j': rnd.randbytes(8),
            tmp_path / 'k': rnd.randbytes(4),
            tmp_path / 'l': rnd.randbytes(256),
            tmp_path / 'm': rnd.randbytes(1),
            tmp_path / 'n': b'',
            tmp_path / 'o': b'',
            tmp_path / 'p': rnd.randbytes(19),
        }
        for file, data in file_contents.items():
            file.write_bytes(data)

        result = await local_repo.snapshot(
            paths=list(file_contents),
            note='<associated note>',
        )

        snapshots = list(local_backend.list_files('snapshots'))
        assert snapshots == [result.location]

        encrypted_body = local_repo.deserialize(local_backend.download(result.location))
        assert encrypted_body.keys() == {'chunks', 'data'}
        assert result.chunks == local_repo.deserialize(
            local_repo.props.decrypt(
                encrypted_body['chunks'],
                local_repo.props.derive_shared_subkey(
                    local_repo.props.hash_digest(encrypted_body['data'])
                ),
            )
        )
        assert result.data == local_repo.deserialize(
            local_repo.props.decrypt(encrypted_body['data'], local_repo.props.userkey)
        )

        expected_order = sorted(
            file_contents.items(), key=lambda x: (len(x[1]), x[0].name)
        )
        # Add padding
        stream = []
        for _, data in expected_order[:-1]:
            stream.append(data + bytes(-len(data) % 4))
        stream.append(expected_order[-1][1])

        expected_digests_it = map(
            local_repo.props.hash_digest, local_repo.props.chunkify(stream)
        )
        # Check the insertion order
        assert result.chunks == list(dict.fromkeys(expected_digests_it))

        assert result.data['note'] == '<associated note>'

        snapshot_files = result.data['files']
        assert len(file_contents) == len(snapshot_files)

        snapshot_files.sort(key=lambda x: x['path'])
        restored_files = []

        for file_data in snapshot_files:
            contents = b''
            file_chunks = sorted(file_data['chunks'], key=lambda x: x['counter'])

            for chunk_data in file_chunks:
                digest = result.chunks[chunk_data['index']]
                chunk_location = local_repo._chunk_digest_to_location(digest)
                chunk_bytes = local_repo.props.decrypt(
                    local_backend.download(chunk_location),
                    local_repo.props.derive_shared_subkey(digest),
                )
                contents += chunk_bytes[chunk_data['range'][0] : chunk_data['range'][1]]

            restored_files.append(contents)

        assert restored_files == [data for _, data in sorted(file_contents.items())]

    @pytest.mark.asyncio
    async def test_unencrypted_data(self, local_backend, local_repo, tmp_path):
        await local_repo.init(
            settings={
                'encryption': None,
                'chunking': {
                    'min_length': 256,
                    'max_length': 512,
                },
            },
        )

        rnd = Random(0)
        file_contents = {
            tmp_path / 'a': rnd.randbytes(4099),
            tmp_path / 'b': rnd.randbytes(32),
            tmp_path / 'c': rnd.randbytes(1023),
            tmp_path / 'd': rnd.randbytes(517),
            tmp_path / 'e': rnd.randbytes(2),
            tmp_path / 'f': rnd.randbytes(128),
            tmp_path / 'g': rnd.randbytes(64),
            tmp_path / 'h': rnd.randbytes(2048),
            tmp_path / 'i': rnd.randbytes(19),
            tmp_path / 'j': rnd.randbytes(8),
            tmp_path / 'k': rnd.randbytes(4),
            tmp_path / 'l': rnd.randbytes(256),
            tmp_path / 'm': rnd.randbytes(1),
            tmp_path / 'n': b'',
            tmp_path / 'o': b'',
            tmp_path / 'p': rnd.randbytes(19),
        }
        for file, data in file_contents.items():
            file.write_bytes(data)

        result = await local_repo.snapshot(
            paths=list(file_contents),
            note='<associated note>',
        )

        snapshots = list(local_backend.list_files('snapshots'))
        snapshot_location = local_repo.get_snapshot_location(
            name=result.name, tag=result.tag
        )
        assert snapshots == [snapshot_location]

        snapshot_body = local_repo.deserialize(
            local_backend.download(snapshot_location)
        )
        assert snapshot_body.keys() == {'chunks', 'data'}
        assert result.chunks == snapshot_body['chunks']
        assert result.data == snapshot_body['data']

        expected_order = sorted(
            file_contents.items(), key=lambda x: (len(x[1]), x[0].name)
        )
        # Add padding
        stream = []
        for _, data in expected_order[:-1]:
            stream.append(data + bytes(-len(data) % 4))
        stream.append(expected_order[-1][1])

        expected_digests_it = map(
            local_repo.props.hash_digest, local_repo.props.chunkify(stream)
        )
        # Check the insertion order
        assert result.chunks == list(dict.fromkeys(expected_digests_it))

        assert result.data['note'] == '<associated note>'

        snapshot_files = result.data['files']
        assert len(file_contents) == len(snapshot_files)

        snapshot_files.sort(key=lambda x: x['path'])
        restored_files = []

        for snapshot_data in snapshot_files:
            contents = b''
            file_chunks = sorted(snapshot_data['chunks'], key=lambda x: x['counter'])

            for chunk_data in file_chunks:
                digest = result.chunks[chunk_data['index']]
                chunk_location = local_repo._chunk_digest_to_location(digest)
                chunk_bytes = local_backend.download(chunk_location)
                contents += chunk_bytes[chunk_data['range'][0] : chunk_data['range'][1]]

            restored_files.append(contents)

        assert restored_files == [data for _, data in sorted(file_contents.items())]

    @pytest.mark.asyncio
    async def test_encrypted_deduplicated_references(self, local_repo, tmp_path):
        await local_repo.init(
            password=b'<password>',
            settings={
                'encryption': {'kdf': {'n': 4}},
                'chunking': {
                    'min_length': 256,
                    'max_length': 256,
                },
            },
        )

        contents = b'A' * 8_192
        file = tmp_path / 'file'
        file.write_bytes(contents)
        result = await local_repo.snapshot(paths=[file])

        assert len(result.data['files']) == 1
        assert len(result.data['files'][0]['chunks']) == 32
        assert len(result.chunks) == 1
        assert result.chunks[0] == local_repo.props.hash_digest(
            next(local_repo.props.chunkify([contents]))
        )

    @pytest.mark.asyncio
    async def test_unencrypted_deduplicated_references(self, local_repo, tmp_path):
        await local_repo.init(
            settings={
                'encryption': None,
                'chunking': {
                    'min_length': 256,
                    'max_length': 256,
                },
            }
        )
        contents = b'A' * 8_192
        file = tmp_path / 'file'
        file.write_bytes(contents)
        result = await local_repo.snapshot(paths=[file])

        assert len(result.data['files']) == 1
        assert len(result.data['files'][0]['chunks']) == 32
        assert len(result.chunks) == 1
        assert result.chunks[0] == local_repo.props.hash_digest(
            next(local_repo.props.chunkify([contents]))
        )

    @pytest.mark.asyncio
    async def test_backend_error_propagation(self, local_backend, local_repo, tmp_path):
        await local_repo.init(
            settings={
                'encryption': None,
                'chunking': {
                    'min_length': 256,
                    'max_length': 512,
                },
            }
        )

        file = tmp_path / 'file'
        file.write_bytes(Random(0).randbytes(1_024))

        class _TestException(Exception):
            pass

        with patch.object(local_backend, 'upload', side_effect=_TestException()):
            with pytest.raises(_TestException):
                await local_repo.snapshot(paths=[file])

        assert list(local_backend.list_files('snapshots/')) == []

    @pytest.mark.asyncio
    async def test_wait_for_chunk_upload(self, local_backend, local_repo, tmp_path):
        await local_repo.init(
            settings={
                'encryption': None,
                'chunking': {
                    'min_length': 256,
                    'max_length': 256,
                },
            }
        )

        data = Random(0).randbytes(1_024)
        file = tmp_path / 'file'
        file.write_bytes(data)

        upload_lock = threading.Lock()
        bytes_consumed = 0

        def upldstream(name, contents, length):
            nonlocal bytes_consumed
            with upload_lock:
                bytes_consumed += length
                bytes_remaining = len(data) - bytes_consumed

            try:
                return Local.upload_stream(local_backend, name, contents, length)
            finally:
                if not bytes_remaining:
                    # Simulate work
                    time.sleep(0.5)

        with patch.object(local_backend, 'upload') as upload_mock, patch.object(
            local_backend, 'upload_stream', side_effect=upldstream
        ) as upload_stream_mock:
            result = await local_repo.snapshot(paths=[file])

        upload_mock.assert_called_once_with(result.location, ANY)
        assert upload_stream_mock.call_count == len(result.data['files'][0]['chunks'])

    @pytest.mark.parametrize('encryption', [None, {'kdf': {'n': 4}}])
    @pytest.mark.asyncio
    async def test_not_locked(self, monkeypatch, local_backend, tmp_path, encryption):
        local_repo = Repository(local_backend, concurrent=5)
        await local_repo.init(
            password=b'<password>',
            settings={'encryption': encryption},
        )

        file = tmp_path / 'file'
        file.write_bytes(Random(0).randbytes(1))

        event = threading.Event()
        wait_for_lock_mock = AsyncMock()

        async def _wait_for_lock(*a, **ka):
            await wait_for_lock_mock(*a, **ka)
            while not event.is_set():
                await asyncio.sleep(0)

        monkeypatch.setattr(local_repo, 'wait_for_lock', _wait_for_lock)

        with patch.object(
            utils,
            'utc_timestamp',
            side_effect=lambda it=iter(
                [local_repo.LOCK_TTP * 23, local_repo.LOCK_TTP * 131]
            ): next(it),
        ), patch.object(local_repo, 'lock_worker') as lock_worker_mock, patch.object(
            local_backend, 'upload'
        ) as upload_mock, patch.object(
            local_backend, 'upload_stream', side_effect=lambda *a, **ka: event.set()
        ) as upload_stream_mock:
            result = await local_repo.snapshot(paths=[file])

        lock_worker_mock.assert_awaited_once_with(
            local_repo.LOCK_TTP * 23, LockTypes.create_read
        )
        wait_for_lock_mock.assert_awaited_once_with(
            local_repo.LOCK_TTP * (23 - 131 + 1), LockTypes.delete
        )
        upload_mock.assert_called_once_with(result.location, ANY)
        upload_stream_mock.assert_called_once()

    @pytest.mark.parametrize('encryption', [None, {'kdf': {'n': 4}}])
    @pytest.mark.asyncio
    async def test_locked(self, monkeypatch, local_backend, tmp_path, encryption):
        local_repo = Repository(local_backend, concurrent=5)
        await local_repo.init(
            password=b'<password>',
            settings={'encryption': encryption},
        )

        file = tmp_path / 'file'
        file.write_bytes(Random(0).randbytes(1))

        event = threading.Event()
        wait_for_lock_mock = AsyncMock()

        async def _wait_for_lock(*a, **ka):
            await wait_for_lock_mock(*a, **ka)
            while not event.is_set():
                await asyncio.sleep(0)
            raise exceptions.Locked

        monkeypatch.setattr(local_repo, 'wait_for_lock', _wait_for_lock)

        with pytest.raises(exceptions.Locked), patch.object(
            utils,
            'utc_timestamp',
            side_effect=lambda it=iter(
                [local_repo.LOCK_TTP * 19, local_repo.LOCK_TTP * 117]
            ): next(it),
        ), patch.object(local_repo, 'lock_worker') as lock_worker_mock, patch.object(
            local_backend, 'upload'
        ) as upload_mock, patch.object(
            local_backend, 'upload_stream', side_effect=lambda *a, **ka: event.set()
        ) as upload_stream_mock:
            await local_repo.snapshot(paths=[file])

        lock_worker_mock.assert_awaited_once_with(
            local_repo.LOCK_TTP * 19, LockTypes.create_read
        )
        wait_for_lock_mock.assert_awaited_once_with(
            local_repo.LOCK_TTP * (19 - 117 + 1), LockTypes.delete
        )
        upload_mock.assert_not_called()
        upload_stream_mock.assert_called_once()


class TestRestore:
    @pytest.mark.asyncio
    async def test_encrypted_data(self, local_repo, tmp_path):
        await local_repo.init(
            password=b'<password>',
            settings={
                'encryption': {'kdf': {'n': 4}},
                'chunking': {
                    'min_length': 256,
                    'max_length': 512,
                },
            },
        )

        rnd = Random(0)
        first_data = rnd.randbytes(4_096)
        first_file = tmp_path / 'first_file'
        first_file.write_bytes(first_data)

        second_data = rnd.randbytes(4_096)
        second_file = tmp_path / 'directory/second_directory/second_file'
        second_file.parent.mkdir(exist_ok=True, parents=True)
        second_file.write_bytes(second_data)

        snapshot_params = await local_repo.snapshot(paths=[first_file, second_file])
        result = await local_repo.restore(
            snapshot_regex=snapshot_params.name, path=tmp_path
        )
        assert set(result.files) == {str(first_file), str(second_file)}
        assert tmp_path.joinpath(*first_file.parts[1:]).read_bytes() == first_data
        assert tmp_path.joinpath(*second_file.parts[1:]).read_bytes() == second_data

    @pytest.mark.asyncio
    async def test_unencrypted_data(self, local_repo, tmp_path):
        await local_repo.init(
            settings={
                'encryption': None,
                'chunking': {
                    'min_length': 256,
                    'max_length': 512,
                },
            }
        )

        rnd = Random(0)
        first_data = rnd.randbytes(4_096)
        first_file = tmp_path / 'first_file'
        first_file.write_bytes(first_data)

        second_data = rnd.randbytes(4_096)
        second_file = tmp_path / 'directory/second_directory/second_file'
        second_file.parent.mkdir(exist_ok=True, parents=True)
        second_file.write_bytes(second_data)

        await local_repo.snapshot(paths=[first_file, second_file])
        result = await local_repo.restore(path=tmp_path)
        assert set(result.files) == {str(first_file), str(second_file)}
        assert tmp_path.joinpath(*first_file.parts[1:]).read_bytes() == first_data
        assert tmp_path.joinpath(*second_file.parts[1:]).read_bytes() == second_data

    @pytest.mark.asyncio
    async def test_defaults_to_latest_file_version(self, local_repo, tmp_path):
        await local_repo.init(
            settings={
                'encryption': None,
                'chunking': {
                    'min_length': 256,
                    'max_length': 512,
                },
            },
        )
        rnd = Random(0)
        file = tmp_path / 'file'
        file.write_bytes(rnd.randbytes(4_096))
        await local_repo.snapshot(paths=[file])

        second_version = rnd.randbytes(4_096)
        file.write_bytes(second_version)
        await local_repo.snapshot(paths=[file])

        result = await local_repo.restore(
            files_regex=re.escape(str(file)), path=tmp_path
        )
        assert result.files == [str(file)]
        assert tmp_path.joinpath(*file.parts[1:]).read_bytes() == second_version

    @pytest.mark.asyncio
    async def test_snapshot_version(self, local_repo, tmp_path):
        await local_repo.init(
            settings={
                'encryption': None,
                'chunking': {
                    'min_length': 256,
                    'max_length': 512,
                },
            },
        )
        rnd = Random(0)
        file = tmp_path / 'file'
        first_version = rnd.randbytes(4_096)
        file.write_bytes(first_version)
        first_snapshot = await local_repo.snapshot(paths=[file])

        file.write_bytes(rnd.randbytes(4_096))
        await local_repo.snapshot(paths=[file])

        result = await local_repo.restore(
            snapshot_regex=first_snapshot.name, path=tmp_path
        )
        assert result.files == [str(file)]
        assert tmp_path.joinpath(*file.parts[1:]).read_bytes() == first_version


class TestDeleteSnapshots:
    @pytest.mark.asyncio
    async def test_encrypted_referenced_independent_key(
        self, local_backend, local_repo, tmp_path
    ):
        file = tmp_path / 'file'
        file.write_bytes(Random(0).randbytes(2_048))

        await local_repo.init(
            password=b'<password>',
            settings={
                'encryption': {'kdf': {'n': 4}},
                'chunking': {
                    'min_length': 512,
                    'max_length': 512,
                },
            },
        )
        first_snapshot = await local_repo.snapshot(paths=[file])
        first_snapshot_paths = [
            local_repo._chunk_digest_to_location(x) for x in first_snapshot.chunks
        ]

        # Add an independent key, unlock the repository, create the same snapshot, delete it
        second_key = (
            await local_repo.add_key(
                password=b'<new password>',
                settings={'encryption': {'kdf': {'n': 4}}},
            )
        ).new_key
        await local_repo.unlock(password=b'<new password>', key=second_key)
        second_snapshot = await local_repo.snapshot(paths=[file])
        second_snapshot_paths = [
            local_repo._chunk_digest_to_location(x) for x in second_snapshot.chunks
        ]
        await local_repo.delete_snapshots([second_snapshot.name])

        assert all(map(local_backend.exists, first_snapshot_paths))
        assert not any(map(local_backend.exists, second_snapshot_paths))
        assert not local_backend.exists(second_snapshot.location)

    @pytest.mark.asyncio
    async def test_encrypted_unreferenced_independent_key(
        self, local_backend, local_repo, tmp_path
    ):
        file = tmp_path / 'file'
        file.write_bytes(Random(0).randbytes(2_048))

        await local_repo.init(
            password=b'<password>',
            settings={
                'encryption': {'kdf': {'n': 4}},
                'chunking': {
                    'min_length': 512,
                    'max_length': 512,
                },
            },
        )
        first_snapshot = await local_repo.snapshot(paths=[file])
        first_snapshot_paths = [
            local_repo._chunk_digest_to_location(x) for x in first_snapshot.chunks
        ]
        # Delete the created reference
        local_backend.delete(first_snapshot.location)

        # Add an independent key, unlock the repository, create the same snapshot, delete it
        second_key = (
            await local_repo.add_key(
                password=b'<new password>',
                settings={'encryption': {'kdf': {'n': 4}}},
            )
        ).new_key
        await local_repo.unlock(password=b'<new password>', key=second_key)
        second_snapshot = await local_repo.snapshot(paths=[file])
        second_snapshot_paths = [
            local_repo._chunk_digest_to_location(x) for x in second_snapshot.chunks
        ]
        await local_repo.delete_snapshots([second_snapshot.name])

        assert all(map(local_backend.exists, first_snapshot_paths))
        assert not any(map(local_backend.exists, second_snapshot_paths))
        assert not local_backend.exists(second_snapshot.location)

    @pytest.mark.asyncio
    async def test_encrypted_referenced_shared_key(
        self, local_backend, local_repo, tmp_path
    ):
        file = tmp_path / 'file'
        file.write_bytes(Random(0).randbytes(2_048))

        await local_repo.init(
            password=b'<password>',
            settings={
                'encryption': {'kdf': {'n': 4}},
                'chunking': {
                    'min_length': 512,
                    'max_length': 512,
                },
            },
        )
        first_snapshot = await local_repo.snapshot(paths=[file])
        first_snapshot_paths = [
            local_repo._chunk_digest_to_location(x) for x in first_snapshot.chunks
        ]

        # Add a shared key, unlock the repository, create the same snapshot, delete it
        second_key = (
            await local_repo.add_key(
                password=b'<new password>',
                settings={'encryption': {'kdf': {'n': 4}}},
                shared=True,
            )
        ).new_key
        await local_repo.unlock(password=b'<new password>', key=second_key)
        second_snapshot = await local_repo.snapshot(paths=[file])
        second_snapshot_paths = [
            local_repo._chunk_digest_to_location(x) for x in second_snapshot.chunks
        ]
        await local_repo.delete_snapshots([second_snapshot.name])

        assert all(map(local_backend.exists, first_snapshot_paths))
        assert all(map(local_backend.exists, second_snapshot_paths))
        assert not local_backend.exists(second_snapshot.location)

    @pytest.mark.asyncio
    async def test_encrypted_unreferenced_shared_key(
        self, local_backend, local_repo, tmp_path
    ):
        file = tmp_path / 'file'
        file.write_bytes(Random(0).randbytes(2_048))

        await local_repo.init(
            password=b'<password>',
            settings={
                'encryption': {'kdf': {'n': 4}},
                'chunking': {
                    'min_length': 512,
                    'max_length': 512,
                },
            },
        )
        first_snapshot = await local_repo.snapshot(paths=[file])
        first_snapshot_paths = [
            local_repo._chunk_digest_to_location(x) for x in first_snapshot.chunks
        ]
        # Delete the created reference
        local_backend.delete(first_snapshot.location)

        # Add a shared key, unlock the repository, create the same snapshot, delete it
        second_key = (
            await local_repo.add_key(
                password=b'<new password>',
                settings={'encryption': {'kdf': {'n': 4}}},
                shared=True,
            )
        ).new_key
        await local_repo.unlock(password=b'<new password>', key=second_key)
        second_snapshot = await local_repo.snapshot(paths=[file])
        second_snapshot_paths = [
            local_repo._chunk_digest_to_location(x) for x in second_snapshot.chunks
        ]

        await local_repo.delete_snapshots([second_snapshot.name])

        assert not any(map(local_backend.exists, first_snapshot_paths))
        assert not any(map(local_backend.exists, second_snapshot_paths))
        assert not local_backend.exists(second_snapshot.location)

    @pytest.mark.asyncio
    async def test_unencrypted_referenced(self, local_backend, local_repo, tmp_path):
        file = tmp_path / 'file'
        file.write_bytes(Random(0).randbytes(2_048))

        await local_repo.init(
            settings={
                'encryption': None,
                'chunking': {
                    'min_length': 512,
                    'max_length': 512,
                },
            },
        )
        snapshot = await local_repo.snapshot(paths=[file])
        snapshot_paths = [
            local_repo._chunk_digest_to_location(x) for x in snapshot.chunks
        ]
        await local_repo.snapshot(paths=[file])
        await local_repo.delete_snapshots([snapshot.name])
        assert all(map(local_backend.exists, snapshot_paths))
        assert not local_backend.exists(snapshot.location)

    @pytest.mark.asyncio
    async def test_unencrypted_unreferenced(self, local_backend, local_repo, tmp_path):
        file = tmp_path / 'file'
        file.write_bytes(Random(0).randbytes(2_048))

        await local_repo.init(
            settings={
                'encryption': None,
                'chunking': {
                    'min_length': 512,
                    'max_length': 512,
                },
            },
        )
        snapshot = await local_repo.snapshot(paths=[file])
        snapshot_paths = [
            local_repo._chunk_digest_to_location(x) for x in snapshot.chunks
        ]

        await local_repo.delete_snapshots([snapshot.name])

        assert not any(map(local_backend.exists, snapshot_paths))
        assert not local_backend.exists(snapshot.location)

    @pytest.mark.parametrize('encryption', [None, {'kdf': {'n': 4}}])
    @pytest.mark.asyncio
    async def test_not_locked(self, monkeypatch, local_backend, encryption):
        local_repo = Repository(local_backend, concurrent=5)
        await local_repo.init(
            password=b'<password>',
            settings={'encryption': encryption},
        )

        with patch.multiple(local_repo, lock_worker=DEFAULT, wait_for_lock=DEFAULT):
            snapshot = await local_repo.snapshot(paths=[])

        with patch.object(
            utils,
            'utc_timestamp',
            side_effect=lambda it=iter(
                [local_repo.LOCK_TTP * 37, local_repo.LOCK_TTP * 157]
            ): next(it),
        ), patch.object(local_repo, 'lock_worker') as lock_worker_mock, patch.object(
            local_repo, 'wait_for_lock'
        ) as wait_for_lock_mock, patch.object(
            local_backend, 'delete'
        ) as delete_mock:
            await local_repo.delete_snapshots([snapshot.name])

        lock_worker_mock.assert_awaited_once_with(
            local_repo.LOCK_TTP * 37, LockTypes.delete
        )
        wait_for_lock_mock.assert_awaited_once_with(
            local_repo.LOCK_TTP * (37 - 157 + 1), LockTypes.create_read
        )
        delete_mock.assert_called_once_with(snapshot.location)

    @pytest.mark.parametrize('encryption', [None, {'kdf': {'n': 4}}])
    @pytest.mark.asyncio
    async def test_locked(self, monkeypatch, local_backend, encryption):
        local_repo = Repository(local_backend, concurrent=5)
        await local_repo.init(
            password=b'<password>',
            settings={'encryption': encryption},
        )

        with patch.multiple(local_repo, lock_worker=DEFAULT, wait_for_lock=DEFAULT):
            snapshot = await local_repo.snapshot(paths=[])

        with pytest.raises(exceptions.Locked), patch.object(
            utils,
            'utc_timestamp',
            side_effect=lambda it=iter(
                [local_repo.LOCK_TTP * 41, local_repo.LOCK_TTP * 161]
            ): next(it),
        ), patch.object(local_repo, 'lock_worker') as lock_worker_mock, patch.object(
            local_repo, 'wait_for_lock', side_effect=exceptions.Locked
        ) as wait_for_lock_mock, patch.object(
            local_backend, 'delete'
        ) as delete_mock:
            await local_repo.delete_snapshots([snapshot.name])

        lock_worker_mock.assert_awaited_once_with(
            local_repo.LOCK_TTP * 41, LockTypes.delete
        )
        wait_for_lock_mock.assert_awaited_once_with(
            local_repo.LOCK_TTP * (41 - 161 + 1), LockTypes.create_read
        )
        delete_mock.assert_not_called()


class TestClean:
    @pytest.mark.asyncio
    async def test_encrypted_referenced_independent_key(
        self, local_backend, local_repo, tmp_path
    ):
        file = tmp_path / 'file'
        file.write_bytes(Random(0).randbytes(2_048))

        await local_repo.init(
            password=b'<password>',
            settings={
                'encryption': {'kdf': {'n': 4}},
                'chunking': {
                    'min_length': 512,
                    'max_length': 512,
                },
            },
        )
        snapshot = await local_repo.snapshot(paths=[file])
        chunks_paths = [
            local_repo._chunk_digest_to_location(x) for x in snapshot.chunks
        ]

        # Add an independent key, unlock the repository, attempt to clean up
        second_key = (
            await local_repo.add_key(
                password=b'<new password>',
                settings={'encryption': {'kdf': {'n': 4}}},
            )
        ).new_key
        await local_repo.unlock(password=b'<new password>', key=second_key)
        await local_repo.clean()

        assert all(map(local_backend.exists, chunks_paths))

    @pytest.mark.asyncio
    async def test_encrypted_unreferenced_independent_key(
        self, local_backend, local_repo, tmp_path
    ):
        file = tmp_path / 'file'
        file.write_bytes(Random(0).randbytes(2_048))

        await local_repo.init(
            password=b'<password>',
            settings={
                'encryption': {'kdf': {'n': 4}},
                'chunking': {
                    'min_length': 512,
                    'max_length': 512,
                },
            },
        )
        snapshot = await local_repo.snapshot(paths=[file])
        chunks_paths = [
            local_repo._chunk_digest_to_location(x) for x in snapshot.chunks
        ]
        # Delete the created reference
        local_backend.delete(snapshot.location)

        # Add an independent key, unlock the repository, attempt to clean up
        second_key = (
            await local_repo.add_key(
                password=b'<new password>',
                settings={'encryption': {'kdf': {'n': 4}}},
            )
        ).new_key
        await local_repo.unlock(password=b'<new password>', key=second_key)
        await local_repo.clean()

        assert all(map(local_backend.exists, chunks_paths))

    @pytest.mark.asyncio
    async def test_encrypted_referenced_shared_key(
        self, local_backend, local_repo, tmp_path
    ):
        file = tmp_path / 'file'
        file.write_bytes(Random(0).randbytes(2_048))

        await local_repo.init(
            password=b'<password>',
            settings={
                'encryption': {'kdf': {'n': 4}},
                'chunking': {
                    'min_length': 512,
                    'max_length': 512,
                },
            },
        )
        snapshot = await local_repo.snapshot(paths=[file])
        chunks_paths = [
            local_repo._chunk_digest_to_location(x) for x in snapshot.chunks
        ]

        # Add a shared key, unlock the repository, recreate the same snapshot,
        # attempt to clean up
        second_key = (
            await local_repo.add_key(
                password=b'<new password>',
                settings={'encryption': {'kdf': {'n': 4}}},
                shared=True,
            )
        ).new_key
        await local_repo.unlock(password=b'<new password>', key=second_key)
        await local_repo.clean()

        assert all(map(local_backend.exists, chunks_paths))

    @pytest.mark.asyncio
    async def test_encrypted_unreferenced_shared_key(
        self, local_backend, local_repo, tmp_path
    ):
        file = tmp_path / 'file'
        file.write_bytes(Random(0).randbytes(2_048))

        await local_repo.init(
            password=b'<password>',
            settings={
                'encryption': {'kdf': {'n': 4}},
                'chunking': {
                    'min_length': 512,
                    'max_length': 512,
                },
            },
        )
        snapshot = await local_repo.snapshot(paths=[file])
        chunks_paths = [
            local_repo._chunk_digest_to_location(x) for x in snapshot.chunks
        ]
        # Delete the created reference
        local_backend.delete(snapshot.location)

        # Add a shared key, unlock the repository, attempt to clean up
        second_key = (
            await local_repo.add_key(
                password=b'<new password>',
                settings={'encryption': {'kdf': {'n': 4}}},
                shared=True,
            )
        ).new_key
        await local_repo.unlock(password=b'<new password>', key=second_key)
        await local_repo.clean()

        assert not any(map(local_backend.exists, chunks_paths))

    @pytest.mark.asyncio
    async def test_unencrypted_unreferenced(self, local_backend, local_repo, tmp_path):
        file = tmp_path / 'file'
        file.write_bytes(Random(0).randbytes(2_048))

        await local_repo.init(
            settings={
                'encryption': None,
                'chunking': {
                    'min_length': 512,
                    'max_length': 512,
                },
            },
        )
        snapshot = await local_repo.snapshot(paths=[file])
        chunks_paths = [
            local_repo._chunk_digest_to_location(x) for x in snapshot.chunks
        ]

        # Delete the created reference
        local_backend.delete(snapshot.location)
        # Attempt to clean up
        await local_repo.clean()

        assert not any(map(local_backend.exists, chunks_paths))

    @pytest.mark.asyncio
    async def test_unencrypted_referenced(self, local_backend, local_repo, tmp_path):
        file = tmp_path / 'file'
        file.write_bytes(Random(0).randbytes(2_048))

        await local_repo.init(
            settings={
                'encryption': None,
                'chunking': {
                    'min_length': 512,
                    'max_length': 512,
                },
            },
        )
        snapshot = await local_repo.snapshot(paths=[file])
        chunks_paths = [
            local_repo._chunk_digest_to_location(x) for x in snapshot.chunks
        ]
        # Delete the created reference
        local_backend.delete(snapshot.location)
        # Recreate the same snapshot
        await local_repo.snapshot(paths=[file])
        # Attempt to clean up
        await local_repo.clean()

        assert all(map(local_backend.exists, chunks_paths))


class TestUpload:
    @pytest.fixture(autouse=True)
    def change_cwd(self, tmp_path):
        before = os.getcwd()
        os.chdir(tmp_path)
        yield
        os.chdir(before)

    @pytest.mark.asyncio
    async def test_within_cwd(self, tmp_path):
        backend = Local(tmp_path / 'backend')
        repository = Repository(backend, concurrent=5, exclusive=True)

        files_base_path = tmp_path / 'files'
        contents = {
            files_base_path / 'file': b'\x04\x05\x06',
            files_base_path / 'directory/file': b'\x00\x01\x02\x03',
            files_base_path / 'another/directory/another-file': b'',
        }
        for path, data in contents.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

        await repository.upload(
            [
                files_base_path / 'file',
                files_base_path / 'directory',
                files_base_path / 'another',
            ]
        )
        assert set(backend.list_files()) == {
            'files/file',
            'files/directory/file',
            'files/another/directory/another-file',
        }
        assert backend.download('files/file') == contents[files_base_path / 'file']
        assert (
            backend.download('files/directory/file')
            == contents[files_base_path / 'directory/file']
        )
        assert (
            backend.download('files/another/directory/another-file')
            == contents[files_base_path / 'another/directory/another-file']
        )

    @pytest.mark.asyncio
    async def test_overwrites(self, tmp_path):
        backend = Local(tmp_path / 'backend')
        backend.upload('files/file', b'<old data>')

        files_base_path = tmp_path / 'files'
        files_base_path.mkdir()
        (files_base_path / 'file').write_bytes(b'<updated data>')

        repository = Repository(backend, concurrent=5, exclusive=True)

        await repository.upload([files_base_path / 'file'])
        assert set(backend.list_files()) == {'files/file'}
        assert backend.download('files/file') == b'<updated data>'

    @pytest.mark.asyncio
    async def test_skip_existing(self, tmp_path):
        backend = Local(tmp_path / 'backend')
        backend.upload('files/file', b'<old data>')

        files_base_path = tmp_path / 'files'
        files_base_path.mkdir()
        (files_base_path / 'file').write_bytes(b'<updated data>')

        repository = Repository(backend, concurrent=5, exclusive=True)

        await repository.upload([files_base_path / 'file'], skip_existing=True)
        assert set(backend.list_files()) == {'files/file'}
        assert backend.download('files/file') == b'<old data>'
