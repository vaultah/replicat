import os

import pytest
from replicat import exceptions
from replicat.repository import Repository


@pytest.mark.asyncio
async def test_encrypted_init(local_backend):
    repo = Repository(local_backend, concurrent=1)

    with pytest.raises(exceptions.ReplicatError):
        # No password, and the "no encryption" flag was not set
        await repo.init()

    await repo.init(password=b'password', settings={'encryption.kdf.n': 4})
    assert repo.properties.encrypted


@pytest.mark.asyncio
async def test_encrypted_unlock(local_backend):
    repo = Repository(local_backend, concurrent=1)
    params = await repo.init(password=b'password', settings={'encryption.kdf.n': 4})

    with pytest.raises(exceptions.ReplicatError):
        # No password
        await repo.unlock(key=params.key)

    with pytest.raises(exceptions.ReplicatError):
        # No key
        await repo.unlock(password=b'password')

    await repo.unlock(password=b'password', key=params.key)
    await repo.unlock(password=b'password', key=repo.serialize(params.key))
    assert repo.properties.encrypted


@pytest.mark.asyncio
async def test_encrypted_snapshot(local_backend, tmp_path):
    repo = Repository(backend=local_backend, concurrent=5)
    params = await repo.init(
        password=b'<password>',
        settings={
            'encryption.kdf.n': 4,
            'chunking.min_length': 256,
            'chunking.max_length': 512
        }
    )
    await repo.unlock(password=b'<password>', key=params.key)

    canonical_files = []
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
        'm': 0
    }

    for name, size in sizes.items():
        file = tmp_path / name
        file.write_bytes(os.urandom(size))
        canonical_files.append(file)

    result = await repo.snapshot(paths=canonical_files)
    assert len([*local_backend.list_files('snapshots')]) == 1
    assert len([*local_backend.list_files(f'snapshots/{result.snapshot}')]) == 1

    # Small files come first
    canonical_files.reverse()
    snapshot_files = sorted(result.data['files'], key=lambda x: x['name'], reverse=True)
    assert len(canonical_files) == len(snapshot_files)
    restored_files = []

    for file, snapshot_data in zip(canonical_files, snapshot_files):
        file_snapshot = b''

        for chunk in sorted(snapshot_data['chunks'], key=lambda x: x['counter']):
            chunk_name = chunk['name']
            chunk_path, = local_backend.list_files(f'data/{chunk_name[:2]}/{chunk_name}')
            path = local_backend.path / chunk_path
            contents = path.read_bytes()

            shared_key = repo.properties.derive_shared_key(bytes.fromhex(chunk['digest']))
            decrypted_chunk = repo.properties.decrypt(contents, shared_key)
            file_snapshot += decrypted_chunk[chunk['start']:chunk['end']]

        restored_files.append(file_snapshot)

    assert all(x.read_bytes() == y for x, y in zip(canonical_files, restored_files))
