import asyncio
import inspect
import random
import time
from base64 import standard_b64encode
from concurrent.futures import ThreadPoolExecutor

import pytest
from replicat import utils, exceptions

# TODO: tests for make_parser


class PlainBackend:
    def __init__(self, arg):
        self.results = arg

    @utils.requires_auth
    def action(self):
        self.results.append('CALL')
        time.sleep(random.random() / 5)

        if random.random() > 0.75:
            self.results.append('ERROR')
            raise exceptions.AuthRequired

        self.results.append('SUCCESS')

    def authenticate(self):
        time.sleep(0.5)
        self.results.append('AUTH')


class AsyncBackend:
    def __init__(self, arg):
        self.results = arg

    @utils.requires_auth
    async def action(self):
        self.results.append('CALL')
        await asyncio.sleep(random.random() / 5)

        if random.random() > 0.75:
            self.results.append('ERROR')
            raise exceptions.AuthRequired

        self.results.append('SUCCESS')

    async def authenticate(self):
        await asyncio.sleep(0.5)
        self.results.append('AUTH')


def test_flat_to_nested():
    good = {'a': 1, 'b.a': 2, 'b.b': 3, 'c.d.e': 4}
    good_expected = {'a': 1, 'b': {'a': 2, 'b': 3}, 'c': {'d': {'e': 4}}}
    assert utils.flat_to_nested(good) == good_expected

    # Order of keys must not change anything
    bad = [
        dict.fromkeys(['a.b', 'a.b.c.d']),
        dict.fromkeys(['a.b.c.d', 'a.b']),
        dict.fromkeys(['a', 'a.b']),
        dict.fromkeys(['a.b.c', 'a.b'])
    ]
    for x in bad:
        with pytest.raises(exceptions.ReplicatError) as e:
            utils.flat_to_nested(x)


def test_bytestring_serialization():
    raw = b'<bytes>'
    serialized = utils.type_hint(raw)
    assert serialized == {'!bytes': str(standard_b64encode(raw), 'ascii')}
    deserialized = utils.type_reverse(serialized)
    assert deserialized == raw


def test_safe_kwargs():
    mixed_args = lambda a, b=1, *c, d, e=1, **f: None
    args = {x: x for x in mixed_args.__code__.co_varnames}
    assert utils.safe_kwargs(mixed_args, args) == {'d': 'd', 'e': 'e'}


# NOTE: `list.append` may not be thread-safe in other implementations
@pytest.mark.parametrize('backend_type',
    [PlainBackend, AsyncBackend],
    ids=['threads', 'async'])
@pytest.mark.asyncio
async def test_requires_auth(backend_type):
    jobs, rs = 20, []
    backend = backend_type(rs)

    if inspect.iscoroutinefunction(backend.action):
        tasks = [backend.action() for _ in range(jobs)]
    else:
        loop = asyncio.get_running_loop()
        executor = ThreadPoolExecutor(max_workers=jobs)
        tasks = [loop.run_in_executor(executor, backend.action) for _ in range(jobs)]

    await asyncio.gather(*tasks, return_exceptions=True)

    # Must request authentication at the very beginning
    assert rs[0] == 'AUTH'
    # Test the test correctness
    assert rs.count('ERROR') > 0
    # In the end, all jobs were completed
    assert rs.count('SUCCESS') == jobs
    # Number of calls
    assert rs.count('CALL') == jobs + rs.count('ERROR')
    # There must be fewer authentications (not counting the first one) than errors
    assert rs.count('AUTH') - 1 <= rs.count('ERROR')
