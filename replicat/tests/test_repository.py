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
    temp = Repository(local_backend, concurrent=1)
    config = await temp.init(password=b'password', settings={'encryption.kdf.n': 4})
    repo = Repository(local_backend, concurrent=1)

    with pytest.raises(exceptions.ReplicatError):
        # No password
        await repo.unlock(key=config.key)

    with pytest.raises(exceptions.ReplicatError):
        # No key
        await repo.unlock(password=b'password')

    await repo.unlock(password=b'password', key=config.key)
    await repo.unlock(password=b'password', key=repo.serialize(config.key))
    assert repo.properties.encrypted
