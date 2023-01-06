import dataclasses
import inspect
import logging
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from appdirs import user_cache_dir, user_config_dir

from .. import exceptions
from . import compat, guess_type, parse_repository

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = Path(user_config_dir('replicat'), 'replicat.toml')
DEFAULTS_SECTION = 'default'

DEFAULT_REPOSITORY = ('local', os.getcwd())
DEFAULT_CONCURRENT = 5
DEFAULT_CACHE_DIRECTORY = Path(user_cache_dir('replicat', 'replicat'))
DEFAULT_LOG_LEVEL = logging.WARNING


# NOTE: Python uses the file system encoding in surrograteescape mode
# for command line arguments AND os.environ. And we need bytes. So yeah.
# Still, we'll use os.environb when available.
def _get_environb(var):
    try:
        return os.environb[os.fsencode(var)]
    except AttributeError:
        string_value = os.environ[var]
        return os.fsencode(string_value)


def _check_mutually_exclusive(mapping, *keys):
    it = (k in mapping for k in keys)
    if any(it) and any(it):
        raise exceptions.InvalidConfig(
            'Options {} are mutually exclusive'.format(', '.join(map(repr, keys)))
        )


def _check_natural_number(value):
    if isinstance(value, str):
        value = int(value)
    elif not isinstance(value, int):
        raise ValueError(f'{value!r} is not an integer')

    if value < 1:
        raise ValueError(f'{value!r} is not an valid value')

    return value


def _check_boolean(value):
    if isinstance(value, str):
        value = guess_type(value)

    if not isinstance(value, bool):
        raise ValueError(f'{value!r} is not a boolean')

    return value


def _read_bytes(path):
    return Path(path).expanduser().read_bytes()


def _convert_log_level(value):
    supported_levels = {
        'fatal': logging.FATAL,
        'critical': logging.CRITICAL,
        'error': logging.ERROR,
        'warning': logging.WARNING,
        'info': logging.INFO,
        'debug': logging.DEBUG,
    }

    try:
        return supported_levels[value.lower()]
    except KeyError:
        raise ValueError(f'{value!r} is not a supported log level') from None


def read_config(path=None, *, profile=None):
    if path is None:
        path = DEFAULT_CONFIG_PATH

    text = f'[{DEFAULTS_SECTION}]\n' + Path(path).read_text(encoding='utf-8')
    try:
        sections = compat.toml.loads(text)
    except compat.toml.TOMLDecodeError as e:
        raise exceptions.InvalidConfig(f'Config at {path} is invalid') from e
    else:
        defaults = sections[DEFAULTS_SECTION]
        if profile is not None:
            try:
                defaults.update(sections[profile])
            except KeyError as e:
                raise LookupError(f'Unrecognized profile {profile!r}') from e

        return defaults


class BaseConfig(ABC):
    @abstractmethod
    def apply_known(self, mapping) -> Dict[str, Any]:
        return {}

    @abstractmethod
    def apply_env(self) -> None:
        return None

    def _validate_set(self, method, key, validator=None, *, field):
        try:
            value = method(key)
        except KeyError:
            pass
        else:
            if validator is not None:
                setattr(self, field, validator(value))
            else:
                setattr(self, field, value)

    def getset(self, mapping, key, validator=None, *, field):
        self._validate_set(mapping.__getitem__, key, validator, field=field)

    def popset(self, mapping, key, validator=None, *, field):
        self._validate_set(mapping.pop, key, validator, field=field)

    def dict(self):
        return {
            field.name: getattr(self, field.name) for field in dataclasses.fields(self)
        }


@dataclasses.dataclass
class Config(BaseConfig):
    repository: Tuple[str, str] = DEFAULT_REPOSITORY
    quiet: bool = False
    concurrent: int = DEFAULT_CONCURRENT
    cache_directory: Optional[Path] = DEFAULT_CACHE_DIRECTORY
    password: Optional[bytes] = None
    key: Optional[bytes] = None
    log_level: Optional[int] = DEFAULT_LOG_LEVEL

    def apply_known(self, mapping):
        _check_mutually_exclusive(mapping, 'key', 'key-file')
        _check_mutually_exclusive(mapping, 'password', 'password-file')

        remaining = mapping.copy()
        self.popset(remaining, 'repository', parse_repository, field='repository')
        self.popset(remaining, 'concurrent', _check_natural_number, field='concurrent')
        self.popset(remaining, 'hide-progress', _check_boolean, field='quiet')
        self.popset(remaining, 'cache-directory', Path, field='cache_directory')

        if _check_boolean(remaining.pop('no-cache', False)):
            self.cache_directory = None

        self.popset(remaining, 'password', str.encode, field='password')
        self.popset(remaining, 'password-file', _read_bytes, field='password')
        self.popset(remaining, 'key', str.encode, field='key')
        self.popset(remaining, 'key-file', _read_bytes, field='key')
        self.popset(remaining, 'log-level', _convert_log_level, field='log_level')
        return remaining

    def apply_env(self):
        self.getset(
            os.environ, 'REPLICAT_REPOSITORY', parse_repository, field='repository'
        )
        try:
            self.password = _get_environb('REPLICAT_PASSWORD')
        except KeyError:
            pass


class BaseBackendConfig(BaseConfig):
    def apply_known(self, mapping):
        remaining = mapping.copy()

        for field in dataclasses.fields(self):
            hyphenated_name = field.name.replace('_', '-')
            self.popset(remaining, hyphenated_name, guess_type, field=field.name)

        return remaining

    def apply_env(self):
        for field in dataclasses.fields(self):
            env_name = backend_env_option(self.backend_type, field.name)
            self.getset(os.environ, env_name, guess_type, field=field.name)


def backend_env_option(backend_type, option_name):
    return f'{backend_type.short_name}_{option_name}'.upper()


def config_for_backend(cls, missing=None):
    params = inspect.signature(cls).parameters
    fields = []

    for name, arg in params.items():
        # Take just keyword-only arguments
        if arg.kind is not arg.KEYWORD_ONLY:
            continue

        annotation = arg.annotation if arg.annotation is not arg.empty else None
        default = arg.default if arg.default is not arg.empty else missing
        fields.append((name, annotation, default))

    return dataclasses.make_dataclass(
        f'{cls.short_name}BackendConfig',
        fields=fields,
        bases=(BaseBackendConfig,),
        namespace={'backend_type': cls},
    )
