import asyncio
import logging
import os
import threading
import time
from base64 import standard_b64encode
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest

from replicat import exceptions, utils
from replicat.backends.base import Backend
from replicat.utils import cli, config, fs

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


def test_parser_for_backend():
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

    parser = cli.parser_for_backend(A)
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


def test_parse_cli_settings():
    args_list = [
        '--first-long-name.very-empty',
        '--second-long-name.single-value',
        'none',
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
        '--fifth',
        'what?',
        '--sixth',
        '1_234',
        '--seventh-trailing',
    ]
    parsed, unknown = cli.parse_cli_settings(args_list)
    assert len(parsed) == 5
    assert parsed['second_long_name.single_value'] is None
    assert parsed['third_long_name.multiple_values'] == 1
    assert parsed['fourth_long_name.final'] == 'abc'
    assert parsed['fifth'] == 'what?'
    assert parsed['sixth'] == 1234
    assert unknown == [
        '--first-long-name.very-empty',
        '2',
        '3',
        '-a',
        '4',
        '5',
        'def',
        '--seventh-trailing',
    ]


@pytest.mark.parametrize(
    'patterns, expected_combined',
    [
        ([], ''),
        (['a'], 'a'),
        (['^a', '^b', 'c$'], '^a|^b|c$'),
    ],
)
def test_combine_regexes(patterns, expected_combined):
    assert utils.combine_regexes(patterns) == expected_combined


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

    entries = fs.iterative_scandir(tmp_path)
    assert sorted(map(os.fspath, entries)) == [
        str(tmp_path / 'A/B/C/D/somefile'),
        str(tmp_path / 'A/B/K/differentfile'),
        str(tmp_path / 'Y/yetanotherfile'),
    ]


class TestReadConfig:
    @pytest.fixture
    def config_path(self, tmp_path):
        path = tmp_path / '.config/test.cfg'
        path.parent.mkdir(parents=True, exist_ok=False)
        return path

    def test_ok(self, config_path):
        config_path.write_text(
            """
            first-option = 1
            second-option = "a"

            [first-section]


            [second_section]
            third_option = "b"

            [ with-spaces_weird   ]
            second-option="c"
            boolean_option = false
            """
        )
        assert config.read_config(config_path) == {
            'first-option': 1,
            'second-option': 'a',
        }
        assert config.read_config(config_path, profile='second_section') == {
            'first-option': 1,
            'second-option': 'a',
            'third_option': 'b',
        }
        assert config.read_config(config_path, profile='with-spaces_weird') == {
            'first-option': 1,
            'second-option': 'c',
            'boolean_option': False,
        }

    def test_default_already_present(self, config_path):
        config_path.write_text(
            f"""
            [{config.DEFAULTS_SECTION}]
            first-option = 1
            second-option = a
            """
        )
        with pytest.raises(exceptions.InvalidConfig):
            config.read_config(config_path)

    def test_no_matching_section(self, config_path):
        config_path.write_text(
            """
            only-default-option = 1
            [proper-section-name]
            section-option = 1
            """
        )
        with pytest.raises(LookupError):
            config.read_config(config_path, profile='bad-section-name')

    @pytest.mark.parametrize(
        'contents',
        [
            """
            duplicate-option = 1
            duplicate-option = 2
            """,
            """
            no-value
            yes-value = 'yes'
            """,
        ],
    )
    def test_invalid_config(self, config_path, contents):
        config_path.write_text(contents)
        with pytest.raises(exceptions.InvalidConfig):
            config.read_config(config_path)


class TestConfig:
    @pytest.mark.parametrize(
        'options',
        [
            ('key', 'key-file'),
            ('password', 'password-file'),
        ],
    )
    def test_mutually_exclusive(self, options):
        cfg = config.Config()
        with pytest.raises(exceptions.InvalidConfig):
            cfg.apply_known(dict.fromkeys(options, '<some value>'))

    def test_apply_repository_ok(self):
        cfg = config.Config()
        cfg.apply_known({'repository': 'somebackend:<some param>'})
        assert cfg.repository == ('somebackend', '<some param>')

    def test_apply_repository_fail(self):
        cfg = config.Config()
        with pytest.raises(ValueError):
            cfg.apply_known({'repository': '<non-identifier>:<some param>'})

    @pytest.mark.parametrize(
        'input_value, converted_value',
        [
            ('789', 789),
            (890, 890),
        ],
    )
    def test_apply_concurrent_ok(self, input_value, converted_value):
        cfg = config.Config()
        cfg.apply_known({'concurrent': input_value})
        assert cfg.concurrent == converted_value

    @pytest.mark.parametrize(
        'input_value', ['789.0', 789.0, '-1', -1, '0', 0, '<not int>']
    )
    def test_apply_concurrent_fail(self, input_value):
        cfg = config.Config()
        with pytest.raises(ValueError):
            cfg.apply_known({'concurrent': input_value})

    @pytest.mark.parametrize(
        'input_value, converted_value',
        [
            ('true', True),
            ('false', False),
            ('TRUE', True),
            (True, True),
            (False, False),
        ],
    )
    def test_apply_quiet_ok(self, input_value, converted_value):
        cfg = config.Config()
        cfg.apply_known({'hide-progress': input_value})
        assert cfg.quiet is converted_value

    @pytest.mark.parametrize('input_value', ['none', '0', 0, 1, '<not bool>'])
    def test_apply_quiet_fail(self, input_value):
        cfg = config.Config()
        with pytest.raises(ValueError):
            cfg.apply_known({'hide-progress': input_value})

    @pytest.mark.parametrize(
        'input_value, converted_value',
        [
            ('string/sub/directory', Path('string/sub/directory')),
            (Path('path/sub/directory'), Path('path/sub/directory')),
        ],
    )
    def test_apply_cache_directory_ok(self, input_value, converted_value):
        cfg = config.Config()
        cfg.apply_known({'cache-directory': input_value})
        assert cfg.cache_directory == converted_value

    @pytest.mark.parametrize(
        'input_value, converted_value',
        [
            ('true', None),
            ('false', Path('dir/file')),
            ('TRUE', None),
            (True, None),
            (False, Path('dir/file')),
        ],
    )
    def test_apply_no_cache_ok(self, input_value, converted_value):
        cfg = config.Config()
        cfg.apply_known({'cache-directory': Path('dir/file'), 'no-cache': input_value})
        assert cfg.cache_directory == converted_value

    @pytest.mark.parametrize('input_value', ['none', '1', '0', 0, 'true    '])
    def test_apply_no_cache_fail(self, input_value):
        cfg = config.Config()
        with pytest.raises(ValueError):
            cfg.apply_known(
                {'cache-directory': Path('dir/file'), 'no-cache': input_value}
            )

    def test_apply_password_ok(self):
        cfg = config.Config()
        cfg.apply_known({'password': '<password as a string>'})
        assert cfg.password == b'<password as a string>'

    def test_apply_password_fail(self):
        cfg = config.Config()
        with pytest.raises(ValueError):
            cfg.apply_known({'password': '\ud861\udd37'})

    def test_apply_password_file_ok(self, tmp_path):
        cfg = config.Config()
        data = bytes(59) + b'\n\n\n\n'
        (tmp_path / 'pwd.text').write_bytes(data)
        cfg.apply_known({'password-file': str(tmp_path / 'pwd.text')})
        assert cfg.password == data

    def test_apply_password_file_fail(self, tmp_path):
        cfg = config.Config()
        with pytest.raises(FileNotFoundError):
            cfg.apply_known({'password-file': str(tmp_path / 'pwd.text')})

    def test_apply_key_ok(self):
        cfg = config.Config()
        cfg.apply_known({'key': '<key string>'})
        assert cfg.key == b'<key string>'

    def test_apply_key_file_ok(self, tmp_path):
        cfg = config.Config()
        data = b'<no validation whatsoever>\n\n\n\n'
        (tmp_path / 'key.text').write_bytes(data)
        cfg.apply_known({'key-file': str(tmp_path / 'key.text')})
        assert cfg.key == data

    def test_apply_key_file_fail(self, tmp_path):
        cfg = config.Config()
        with pytest.raises(FileNotFoundError):
            cfg.apply_known({'key-file': str(tmp_path / 'key.text')})

    @pytest.mark.parametrize(
        'input_value, converted_value',
        [
            ('fatal', logging.FATAL),
            ('critical', logging.CRITICAL),
            ('error', logging.ERROR),
            ('warning', logging.WARNING),
            ('info', logging.INFO),
            ('debug', logging.DEBUG),
        ],
    )
    def test_apply_log_level_ok(self, input_value, converted_value):
        cfg = config.Config()
        cfg.apply_known({'log-level': input_value})
        assert cfg.log_level is converted_value

    @pytest.mark.parametrize('input_value', ['', 'notset', 'warn'])
    def test_apply_log_level_fail(self, input_value):
        cfg = config.Config()
        with pytest.raises(ValueError):
            cfg.apply_known({'log-level': input_value})

    def test_apply_known_returns_unknown(self):
        data = {
            'keyhole': None,
            'key': '<key string>',
            'concurrent': '100',
            'yes-cache': 'false',
            'no-cache': 'true',
        }

        cfg = config.Config()
        unknown = cfg.apply_known(data)
        assert unknown == {'keyhole': None, 'yes-cache': 'false'}
        assert unknown is not data

    def test_apply_env_repository_ok(self):
        cfg = config.Config()
        with patch.dict(os.environ, REPLICAT_REPOSITORY='somebackend:<backend param>'):
            cfg.apply_env()

        assert cfg.repository == ('somebackend', '<backend param>')

    def test_apply_env_repository_fail(self):
        cfg = config.Config()
        with patch.dict(
            os.environ, REPLICAT_REPOSITORY='<not an identifier>:<backend param>'
        ), pytest.raises(ValueError):
            cfg.apply_env()

    def test_apply_env_repository_password_string_ok(self):
        cfg = config.Config()
        with patch.dict(os.environ, REPLICAT_PASSWORD='<plaintext>'):
            cfg.apply_env()

        assert cfg.password == b'<plaintext>'

    @pytest.mark.skipif(
        not os.supports_bytes_environ, reason='OS does not support bytes environ'
    )
    def test_apply_env_repository_password_bytes_ok(self):
        cfg = config.Config()
        with patch.dict(os.environb, {b'REPLICAT_PASSWORD': b'<plaintext>'}):
            cfg.apply_env()

        assert cfg.password == b'<plaintext>'

    def test_dict(self):
        cfg = config.Config(
            cache_directory=None,
            log_level=logging.DEBUG,
            repository=('local', 'some/path'),
        )
        assert cfg.dict() == {
            'repository': ('local', 'some/path'),
            'quiet': False,
            'concurrent': 5,
            'cache_directory': None,
            'password': None,
            'key': None,
            'log_level': logging.DEBUG,
        }


def test_config_for_backend():
    class testbackend:
        short_name = 'TB'

        def __init__(self, a: int = 1, *, b: str, c=None, **kwargs):
            ...

    backend_config_type = config.config_for_backend(testbackend, missing='<empty>')
    assert issubclass(backend_config_type, config.BaseBackendConfig)

    backend_config = backend_config_type()
    assert backend_config.b == '<empty>'
    assert backend_config.c is None
    # No more fields
    assert backend_config.dict() == {'b': '<empty>', 'c': None}


class TestBaseBackendConfig:
    @pytest.fixture
    def backend_type(self):
        class testbackend:
            short_name = 'BAKEND'

            def __init__(
                self,
                a: int = 1,
                *,
                b: str,
                c=None,
                d: bool,
                e,
                f,
                with_underscores=True,
            ):
                ...

        return testbackend

    @pytest.fixture
    def backend_config(self, backend_type):
        return config.config_for_backend(backend_type, missing='<not specified>')()

    def test_apply_known_ok(self, backend_config):
        data = {
            'a': '0',
            'b': '<specified>',
            'd': 'none',
            'f': '-15773',
            'with_underscores': 'true',
            'with-underscores': 'false',
        }
        unknown = backend_config.apply_known(data)
        assert backend_config.b == '<specified>'
        assert backend_config.c is None
        assert backend_config.d is None
        assert backend_config.e == '<not specified>'
        assert backend_config.f == -15773
        assert backend_config.with_underscores is False

        assert unknown == {'a': '0', 'with_underscores': 'true'}
        assert unknown is not data

    def test_apply_env(self, backend_config):
        with patch.dict(
            os.environ,
            BAKEND_B='<specified via env>',
            BAKEND_D='none',
            BAKEND_WITH_UNDERSCORES='1234',
        ):
            backend_config.apply_env()

        assert backend_config.b == '<specified via env>'
        assert backend_config.c is None
        assert backend_config.d is None
        assert backend_config.e == '<not specified>'
        assert backend_config.with_underscores == 1234

    def test_dict(self, backend_config):
        backend_config.e = '<yes specified>'
        assert backend_config.dict() == {
            'b': '<not specified>',
            'c': None,
            'd': '<not specified>',
            'e': '<yes specified>',
            'f': '<not specified>',
            'with_underscores': True,
        }
