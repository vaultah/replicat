import argparse
import ast
import asyncio
import base64
import collections.abc
import functools
import importlib
import inspect
import os
import re
import threading
import weakref
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import httpx

from .. import exceptions
from . import adapters, fs  # noqa

PREFIXES_TABLE = {
    'k': 1000,
    'K': 1000,
    'Ki': 1024,
    'ki': 1024,
    'M': 1000 ** 2,
    'm': 1000 ** 2,
    'Mi': 1024 ** 2,
    'mi': 1024 ** 2,
    'g': 1000 ** 3,
    'G': 1000 ** 3,
    'gi': 1024 ** 3,
    'Gi': 1024 ** 3,
}
UNITS_TABLE = {'B': 1, 'b': Decimal('0.125')}
HUMAN_SIZE_REGEX = (
    r'(?P<value>([\d]*[.])?[\d]+)\s*?(?P<prefix>%s)?(?P<unit>[Bb])?'
    % "|".join(PREFIXES_TABLE)
)


def _backend_tuple(uri):
    parts = uri.split(':', 1)
    if len(parts) < 2:
        name, connection_string = 'local', parts[0]
    else:
        name, connection_string = parts

    mod = importlib.import_module(f'..backends.{name}', package=__package__)
    return (mod.Client, connection_string)


def _read_bytes(arg):
    return Path(arg).read_bytes()


# NOTE: Python uses the file system encoding in surrograteescape mode
# for command line arguments AND os.environ. And we need bytes. So yeah.
# Still, we'll use os.environb when available.
def _get_environb(var, default=None):
    try:
        value = os.environb.get(os.fsencode(var), default)
    except AttributeError:
        value = os.environ.get(var, default)
        if value is not default:
            return os.fsencode(value)
    finally:
        return value


common_options = argparse.ArgumentParser(add_help=False)
common_options.add_argument(
    '-r',
    '--repository',
    type=_backend_tuple,
    dest='repo',
    default=os.environ.get('REPLICAT_REPOSITORY', str(Path())),
)
common_options.add_argument(
    '-q', '--hide-progress', dest='progress', action='store_false'
)
common_options.add_argument('--concurrent', default=5, type=int)
common_options.add_argument('-v', '--verbose', action='count', default=0)
common_options.add_argument('-k', '--key', metavar='KEYFILE', type=_read_bytes)
# All the different ways to provide a repo password
password_options = common_options.add_mutually_exclusive_group()
password_options.add_argument('-p', '--password', type=os.fsencode)
password_options.add_argument(
    '-P',
    '--password-file',
    dest='password',
    metavar='PASSWORD_FILE_PATH',
    type=_read_bytes,
)
common_options.set_defaults(password=_get_environb('REPLICAT_PASSWORD'))


def adapter_from_config(name, **kwargs):
    adapter_type = getattr(adapters, name)
    bound_args = inspect.signature(adapter_type).bind(**kwargs)
    bound_args.apply_defaults()
    adapter_args = bound_args.arguments
    return adapter_type(**adapter_args), adapter_args


def make_parser(*parent_parsers):
    parser = argparse.ArgumentParser(add_help=True)
    # TODO: argparse is broken
    subparsers = parser.add_subparsers(dest='action', required=True)
    subparsers.add_parser('init', parents=parent_parsers)

    list_files_parser = subparsers.add_parser(
        'list-files', parents=parent_parsers, aliases=['lf']
    )
    list_files_parser.add_argument(
        '-S', '--snapshot-regex', help='Regex to filter snapshots'
    )
    list_files_parser.add_argument('-F', '--files-regex', help='Regex to filter files')

    list_snapshots_parser = subparsers.add_parser(
        'list-snapshots', parents=parent_parsers, aliases=['ls']
    )
    list_snapshots_parser.add_argument(
        '-S', '--snapshot-regex', help='Regex to filter snapshots'
    )

    snapshot_parser = subparsers.add_parser('snapshot', parents=parent_parsers)
    snapshot_parser.add_argument('path', nargs='+', type=Path)
    snapshot_parser.add_argument(
        '--limit-rate', '-L', dest='rate_limit', type=human_to_bytes
    )

    restore_parser = subparsers.add_parser('restore', parents=parent_parsers)
    restore_parser.add_argument(
        '-S', '--snapshot-regex', help='Regex to filter snapshots'
    )
    restore_parser.add_argument('-F', '--files-regex', help='Regex to filter files')
    return parser


def parser_from_callable(cls):
    """ Create an ArgumentParser instance based on the keyword-only
        arguments of `cls`'s constructor """
    parser = argparse.ArgumentParser(add_help=False)
    params = inspect.signature(cls).parameters

    for name, arg in params.items():
        # Take just keyword-only arguments
        if arg.kind is not arg.KEYWORD_ONLY:
            continue

        # TODO: annotations?
        if arg.default is not arg.empty:
            default = arg.default
        else:
            default = os.environ.get(f'{cls.__name__.upper()}_{name.upper()}')

        name = name.replace('_', '-')
        parser.add_argument(
            f'--{name}',
            required=arg.default is arg.empty,
            default=default,
            type=guess_type,
        )

    return parser


def human_to_bytes(value):
    match = re.fullmatch(HUMAN_SIZE_REGEX, value)
    if match is None:
        raise ValueError
    groups = match.groupdict()
    bytes_amount = Decimal(groups['value'])
    if groups['prefix'] is not None:
        bytes_amount *= PREFIXES_TABLE[groups['prefix']]
    if groups['unit'] is not None:
        bytes_amount *= UNITS_TABLE[groups['unit']]
    return int(bytes_amount)


def bytes_to_human(value):
    if value < 1_000:
        divisor, unit = 1, 'B'
    elif 1_000 <= value < 1_000 ** 2:
        divisor, unit = 1_000, 'K'
    elif 1_000 ** 2 <= value < 1_000 ** 3:
        divisor, unit = 1_000 ** 2, 'M'
    else:
        divisor, unit = 1_000 ** 3, 'G'

    return f'{round(value / divisor, 2):g}{unit}'


def guess_type(value):
    if value.lower() in {'none', 'false', 'true'}:
        value = value.title()

    try:
        return ast.literal_eval(value)
    except (ValueError, SyntaxError):
        return value


def flat_to_nested(flat, *, sep='.'):
    """ Convert a flat mapping to the equivalent nested/hierarchical
        mapping by splitting keys by the separator """
    root = {}

    for key, value in sorted(flat.items()):
        *ancestors, attribute = key.split(sep)
        current = root
        try:
            for x in ancestors:
                current = current.setdefault(x, {})
            current[attribute] = value
        except (AttributeError, TypeError):
            raise exceptions.ReplicatError('Conflicting options')

    return root


def type_hint(object):
    """ Gets called for objects that can't normally be serialized in JSON.
        We only expect to deal with byte strings right now """
    # TODO: add memoryview?
    if isinstance(object, collections.abc.ByteString):
        return {'!bytes': str(base64.standard_b64encode(object), 'ascii')}
    raise TypeError


def type_reverse(object):
    """ Intended to be used as an object_hook. Converts the JSON object
        returned from type_hint to a Python object of appropriate type """
    try:
        encoded = object.pop('!bytes')
    except KeyError:
        return object
    else:
        return base64.standard_b64decode(encoded)


def safe_kwargs(func, args):
    params = inspect.signature(func).parameters
    return {
        name: args[name]
        for name, arg in params.items()
        if arg.kind is arg.KEYWORD_ONLY and name in args
    }


_async_auth_glock = asyncio.Lock()
_async_auth_locks = weakref.WeakKeyDictionary()
_sync_auth_glock = threading.Lock()
_sync_auth_locks = weakref.WeakKeyDictionary()


def requires_auth(func):
    """ If a decorated backend method (async or plain) raises AuthRequired,
        indicating that the backend authorization is no longer valid,
        the decorator will call authenticate to refresh it """
    # TODO: logging?
    if inspect.iscoroutinefunction(func):

        async def wrapper(self, *a, **ka):
            try:
                self._async_auth_lock
            except AttributeError:
                async with _async_auth_glock:
                    try:
                        lock = _async_auth_locks[self]
                    except KeyError:
                        lock = _async_auth_locks[self] = asyncio.Lock()

                if not lock.locked():
                    async with lock:
                        await self.authenticate()
                        self._async_auth_lock = lock
                else:
                    async with lock:
                        pass

            try:
                return await func(self, *a, **ka)
            except exceptions.AuthRequired:
                if not self._async_auth_lock.locked():
                    async with self._async_auth_lock:
                        await self.authenticate()
                else:
                    async with self._async_auth_lock:
                        pass

                return await wrapper(self, *a, **ka)

    else:

        def wrapper(self, *a, **ka):
            try:
                self._auth_lock
            except AttributeError:
                with _sync_auth_glock:
                    try:
                        lock = _sync_auth_locks[self]
                    except KeyError:
                        lock = _sync_auth_locks[self] = threading.Lock()

                if lock.acquire(blocking=False):
                    self.authenticate()
                    self._auth_lock = lock
                    lock.release()
                else:
                    with lock:
                        pass

            try:
                return func(self, *a, **ka)
            except exceptions.AuthRequired:
                if self._auth_lock.acquire(blocking=False):
                    try:
                        self.authenticate()
                    finally:
                        self._auth_lock.release()
                else:
                    with self._auth_lock:
                        pass

                return wrapper(self, *a, **ka)

    wrapper = functools.wraps(func)(wrapper)
    return wrapper


class async_client:

    """ Creates and stores an httpx.AsyncClient instance when accessed through
        the parent object. It should be only accessed from within async methods.
        """

    def __init__(self, *args, **kwargs):
        self.args, self.kwargs = args, kwargs

    def __get__(self, instance, owner):
        try:
            return self._session
        except AttributeError:
            # loop should be picked up automatically
            self._session = httpx.AsyncClient(*self.args, **self.kwargs)
            return self._session


class DefaultNamespace(SimpleNamespace):
    def __getattr__(self, attr):
        return None
