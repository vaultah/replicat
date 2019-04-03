import argparse
import ast
import asyncio
import base64
import collections.abc
import functools
import importlib
import inspect
import os
import threading
from pathlib import Path
from types import SimpleNamespace

import aiohttp
from .. import exceptions
from . import adapters


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
common_options.add_argument('-r', '--repository', type=_backend_tuple, dest='repo',
            default=os.environ.get('REPLICAT_REPOSITORY', str(Path())))
common_options.add_argument('-q', '--hide-progress', dest='progress', action='store_false')
common_options.add_argument('-c', '--concurrent', default=5, type=int)
common_options.add_argument('-v', '--verbose', action='count', default=0)
common_options.add_argument('-k', '--key', metavar='KEYFILE', type=_read_bytes)
# All the different ways to provide a repo password
password_options = common_options.add_mutually_exclusive_group()
password_options.add_argument('-p', '--password', type=os.fsencode)
password_options.add_argument('-P', '--password-file', dest='password',
                        metavar='PASSWORD_FILE_PATH', type=_read_bytes)
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
    subparsers.add_parser('snapshot', parents=parent_parsers)
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
        default = arg.default if arg.default is not arg.empty else None
        # TODO: annotations?
        name = name.replace('_', '-')
        parser.add_argument(f'--{name}', required=arg.default is arg.empty,
                        default=default, type=guess_type)

    return parser


def guess_type(value):
    if value.lower() in {'none', 'false', 'true'}:
        value = value.title()

    try:
        return ast.literal_eval(value)
    except ValueError:
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
    return {name: args[name] for name, arg in params.items()
                if arg.kind is arg.KEYWORD_ONLY and name in args}


def requires_auth(func):
    """ If a decorated backend method (async or plain) raises AuthRequired,
        indicating that the backend authorization is no longer valid,
        the decorator will call authenticate to refresh it """
    # TODO: logging?
    # TODO: a minor race condition is still possible
    if inspect.iscoroutinefunction(func):
        async def wrapper(self, *a, **ka):
            try:
                try:
                    self._async_auth_lock
                except AttributeError:
                    # First call (within the instance); force authentication
                    self._async_auth_lock = asyncio.Lock()
                    raise exceptions.AuthRequired
                else:
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
                try:
                    self._auth_lock
                except AttributeError:
                    # First call (within the instance); force authentication
                    self._auth_lock = threading.Lock()
                    raise exceptions.AuthRequired
                else:
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


class async_session:

    """ Creates and stores an aiohttp client session when accessed
        through the parent object. It should be accessed from
        within an async function. """

    def __init__(self, *args, **kwargs):
        self.args, self.kwargs = args, kwargs

    def __get__(self, instance, owner):
        try:
            return self.session
        except AttributeError:
            # async loop should be picked up automatically
            self.session = aiohttp.ClientSession(*self.args, **self.kwargs)
            return self.session

    # TODO: atexit?
    def close(self):
        self.session.close()


class DefaultNamespace(SimpleNamespace):
    def __getattr__(self, attr):
        return None
