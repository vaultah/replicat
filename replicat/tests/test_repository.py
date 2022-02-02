import io
import posixpath
import re
import threading
import time
from random import Random
from unittest.mock import patch

import pytest

from replicat import exceptions
from replicat.backends.local import Local
from replicat.utils import adapters


class TestHelperMethods:
    def test_get_chunk_location(self, local_repo):
        location = local_repo.get_chunk_location(
            name='CDEFGHIJKLMN', tag='0123456789AB'
        )
        assert location == posixpath.join(
            local_repo.CHUNK_PREFIX, '0123/4567/89AB/CDEFGHIJKLMN'
        )

    def test_parse_chunk_location(self, local_repo):
        location = posixpath.join(
            local_repo.CHUNK_PREFIX, '0123/4567/89AB/CDEFGHIJKLMN'
        )
        name, tag = local_repo.parse_chunk_location(location)
        assert name == 'CDEFGHIJKLMN'
        assert tag == '0123456789AB'

    def test_get_snapshot_location(self, local_repo):
        location = local_repo.get_snapshot_location(
            name='CDEFGHIJKLMN', tag='0123456789AB'
        )
        assert location == posixpath.join(
            local_repo.SNAPSHOT_PREFIX, '0123/4567/89AB/CDEFGHIJKLMN'
        )

    def test_parse_snapshot_location(self, local_repo):
        location = posixpath.join(
            local_repo.SNAPSHOT_PREFIX, '0123/4567/89AB/CDEFGHIJKLMN'
        )
        name, tag = local_repo.parse_snapshot_location(location)
        assert name == 'CDEFGHIJKLMN'
        assert tag == '0123456789AB'


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

        snapshot_files.sort(key=lambda x: x['name'])
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

        snapshot_files.sort(key=lambda x: x['name'])
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

        assert list(local_backend.list_files('snapshots')) == []

    @pytest.mark.asyncio
    async def test_wait_for_chunk_upload(self, local_backend, local_repo, tmp_path):
        await local_repo.init(
            settings={
                'encryption': None,
                'chunking': {
                    'min_length': 256,
                    'max_length': 512,
                },
            }
        )

        data = Random(0).randbytes(1_024)
        file = tmp_path / 'file'
        file.write_bytes(data)

        upload_lock = threading.Lock()
        bytes_remaining = len(data)

        def upld(name, contents):
            nonlocal bytes_remaining
            with upload_lock:
                if isinstance(contents, io.BytesIO):
                    length = len(contents.getbuffer())
                else:
                    length = len(contents)
                bytes_remaining -= length

            rv = Local.upload(local_backend, name, contents)
            if not bytes_remaining and not name.startswith('snapshots/'):
                # Simulate work
                time.sleep(0.5)

            return rv

        with patch.object(local_backend, 'upload', side_effect=upld) as upload_mock:
            result = await local_repo.snapshot(paths=[file])

        snapshots = list(local_backend.list_files('snapshots/'))
        chunks = list(local_backend.list_files('data/'))
        assert len(snapshots) == 1
        assert len(chunks) > 0
        assert len(snapshots) + len(chunks) == upload_mock.call_count
        assert len(result.data['files'][0]['chunks']) == len(chunks)


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
