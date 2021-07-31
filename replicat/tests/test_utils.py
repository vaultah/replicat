import asyncio
import threading
import time
from base64 import standard_b64encode
from concurrent.futures import ThreadPoolExecutor

import pytest

from replicat import exceptions, utils

# TODO: tests for make_parser


class PlainBackend:
    def __init__(self, arg, raise_on):
        self.results = arg
        self.event = threading.Event()
        self.counter = 0
        self.raise_on = raise_on
        self.lock = threading.Lock()

    @utils.requires_auth
    def action(self):
        self.results.append('CALL')
        with self.lock:
            self.counter += 1

        if self.counter > self.raise_on:
            # These are the retries
            self.results.append('SUCCESS')
        elif self.counter == self.raise_on:
            self.results.append('SUCCESS')
            self.event.set()
        else:
            # Wait for calls to accumulate, make them raise AuthRequired all at once
            self.event.wait()
            self.results.append('ERROR')
            raise exceptions.AuthRequired

    def authenticate(self):
        # Simulate work, wait for all the calls to finish
        if self.counter:
            while True:
                time.sleep(0.5)
                if self.results.count('ERROR') >= self.raise_on - 1:
                    break

        self.results.append('AUTH')


class AsyncBackend:
    def __init__(self, arg, *, raise_on):
        self.results = arg
        self.event = asyncio.Event()
        self.counter = 0
        self.raise_on = raise_on

    @utils.requires_auth
    async def action(self):
        self.results.append('CALL')
        self.counter += 1

        if self.counter > self.raise_on:
            # These are the retries
            self.results.append('SUCCESS')
        elif self.counter == self.raise_on:
            self.results.append('SUCCESS')
            self.event.set()
        else:
            # Wait for calls to accumulate, make them raise AuthRequired all at once
            await self.event.wait()
            self.results.append('ERROR')
            raise exceptions.AuthRequired

    async def authenticate(self):
        # Simulate work, wait for all the calls to finish
        if self.counter:
            while True:
                await asyncio.sleep(0.5)
                if self.results.count('ERROR') >= self.raise_on - 1:
                    break

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
        dict.fromkeys(['a.b.c', 'a.b']),
    ]
    for x in bad:
        with pytest.raises(exceptions.ReplicatError):
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


@pytest.mark.asyncio
async def test_requires_auth_async():
    jobs, rs = 10, []
    backend = AsyncBackend(rs, raise_on=jobs)
    tasks = [backend.action() for _ in range(jobs)]
    await asyncio.gather(*tasks, return_exceptions=True)

    # Must request authentication at the very beginning
    assert rs[0] == 'AUTH'
    # Test the test correctness
    assert rs.count('ERROR') == jobs - 1
    # In the end, all jobs were completed
    assert rs.count('SUCCESS') == jobs
    # Number of calls
    assert rs.count('CALL') == jobs + rs.count('ERROR')
    # There must be exactly two authentications (including the first one)
    assert rs.count('AUTH') == 2


# NOTE: `list.append` may not be thread-safe in other implementations
def test_requires_auth_sync():
    jobs, rs = 10, []
    backend = PlainBackend(rs, raise_on=jobs)
    executor = ThreadPoolExecutor(max_workers=jobs)
    with executor:
        for _ in range(jobs):
            executor.submit(backend.action)

    # Must request authentication at the very beginning
    assert rs[0] == 'AUTH'
    # Test the test correctness
    assert rs.count('ERROR') == jobs - 1
    # In the end, all jobs were completed
    assert rs.count('SUCCESS') == jobs
    # Number of calls
    assert rs.count('CALL') == jobs + rs.count('ERROR')
    # There must be exactly two authentications (including the first one)
    assert rs.count('AUTH') == 2
