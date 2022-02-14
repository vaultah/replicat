import asyncio
import os
import random
import threading
import time
from base64 import standard_b64encode
from concurrent.futures import ThreadPoolExecutor

import pytest

from replicat import exceptions, utils
from replicat.backends.base import Backend

# TODO: tests for make_main_parser


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
def test_requires_auth_threads():
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


def test_type_hint_bytestring():
    raw = b'<bytes>'
    serialized = utils.type_hint(raw)
    assert serialized == {'!b': str(standard_b64encode(raw), 'ascii')}


def test_type_hint_reverse_valid_bytestring():
    serialized = {'!b': str(standard_b64encode(b'<bytes>'), 'ascii')}
    deserialized = utils.type_reverse(serialized)
    assert deserialized == b'<bytes>'


def test_type_hint_reverse_invalid():
    serialized = {'!b': str(standard_b64encode(b'<bytes>'), 'ascii'), 'more': 'data'}
    deserialized = utils.type_reverse(serialized)
    assert deserialized == serialized


@pytest.mark.parametrize(
    'value, expected',
    [
        ('none', None),
        ('None', None),
        ('true', True),
        ('True', True),
        ('False', False),
        ('false', False),
        ('1', 1),
        ('2.0', 2.0),
        ('3j', 3j),
        ('unknown', 'unknown'),
    ],
)
def test_guess_type(value, expected):
    guessed = utils.guess_type(value)
    assert guessed == expected
    assert type(guessed) is type(expected)


@pytest.mark.parametrize(
    'human, bytes_amount',
    [
        ('1b', 0),
        ('1B', 1),
        ('2kB', 2_000),
        ('3K', 3_000),
        ('4.5KB', 4_500),
        ('4KiB', 4_096),
        ('5kiB', 5_120),
        ('6m', 6_000_000),
        ('7M', 7_000_000),
        ('8Mi', 8_388_608),
        ('9g', 9_000_000_000),
        ('10.1Gi', 10_844_792_422),
    ],
)
def test_human_to_bytes(human, bytes_amount):
    assert utils.human_to_bytes(human) == bytes_amount


@pytest.mark.parametrize(
    'bytes_amount, human',
    [
        (0, '0B'),
        (1, '1B'),
        (999, '999B'),
        (1000, '1K'),
        (1_001, '1K'),
        (1_100, '1.1K'),
        (9_900_000, '9.9M'),
        (9_999_999, '10M'),
        (11_116_000_000, '11.12G'),
    ],
)
def test_bytes_to_human(bytes_amount, human):
    assert utils.bytes_to_human(bytes_amount) == human


def test_parser_from_backend_class():
    weird_default = object()

    class A(Backend):
        def __init__(
            self,
            positional,
            *args,
            a=0x6CAB0F071,
            b='<default string>',
            c=weird_default,
            d=False,
            e=True,
            f=None,
            g=None,
            h,
            j,
            **kwargs,
        ):
            pass

    parser = utils.parser_from_backend_class(A)
    known, unknown = parser.parse_known_args(['--g', 'true', '--h', 'H', '--j', '2'])
    assert not unknown
    assert known.a == 0x6CAB0F071
    assert known.b == '<default string>'
    assert known.c is weird_default
    assert known.d is False
    assert known.e is True
    assert known.f is None
    assert known.g is True
    assert known.h == 'H'
    assert known.j == 2


def test_parse_unknown_args():
    args_list = [
        '--first-long-name.very-empty',
        '--second-long-name.single-value',
        'true',
        '--third-long-name.multiple-values',
        '1',
        '2',
        '3',
        '-a',
        '4',
        '5',
        '--fourth-long-name.final',
        'abc',
        'def',
    ]
    parsed_args = utils.parse_unknown_args(args_list)
    assert len(parsed_args) == 3
    assert parsed_args['second_long_name.single_value'] is True
    assert parsed_args['third_long_name.multiple_values'] == [1, 2, 3]
    assert parsed_args['fourth_long_name.final'] == ['abc', 'def']


def test_stream_files(tmp_path):
    mapping = {
        tmp_path / 'a': b'',
        tmp_path / 'b': random.randbytes(1_447),
        tmp_path / 'c': random.randbytes(29),
        tmp_path / 'd': random.randbytes(13),
    }
    for path, contents in mapping.items():
        path.write_bytes(contents)

    pairs = list(utils.fs.stream_files(list(mapping), chunk_size=2_048))
    assert len(pairs) == 4

    stream_mapping = dict(pairs)
    assert stream_mapping == mapping


def test_iterative_scandir(tmp_path):
    (tmp_path / 'A/B/C/D').mkdir(parents=True)
    (tmp_path / 'A/B/C/D/somefile').touch()
    (tmp_path / 'A/B/C/E').mkdir()

    (tmp_path / 'A/B/K').mkdir()
    (tmp_path / 'A/B/K/differentfile').touch()
    (tmp_path / 'A/B/L').mkdir()
    (tmp_path / 'A/B/M').mkdir()

    (tmp_path / 'X').mkdir()
    (tmp_path / 'Y').mkdir()
    (tmp_path / 'Y/yetanotherfile').touch()

    entries = utils.fs.iterative_scandir(tmp_path)
    assert sorted(map(os.fspath, entries)) == [
        str(tmp_path / 'A/B/C/D/somefile'),
        str(tmp_path / 'A/B/K/differentfile'),
        str(tmp_path / 'Y/yetanotherfile'),
    ]
