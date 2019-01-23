import argparse
import asyncio
import base64
import collections.abc
import functools
import importlib
import inspect
import threading
from types import SimpleNamespace

from .. import exceptions


def _storage_tuple(uri):
    parts = uri.split(':', 1)
    if len(parts) < 2:
        name, connection_string = 'local', parts[0]
    else:
        name, connection_string = parts

    mod = importlib.import_module(f'..backends.{name}', package=__package__)
    return (mod.Client, connection_string)


common_parser = argparse.ArgumentParser(add_help=False)
common_parser.add_argument('-c', '--concurrent', default=5, type=int)
common_parser.add_argument('-v', '--verbose', action='count', default=0)
common_parser.add_argument('-P', '--hide-progress', dest='progress', action='store_false')
common_parser.add_argument('-s', '--storage', type=_storage_tuple, required=True)


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
        return {'@binary': str(base64.standard_b64encode(object), 'ascii')}
    raise TypeError


def type_reverse(object):
    """ Intended to be used as an object_hook. Converts the JSON object
        returned from type_hint to a Python object of appropriate type """
    try:
        encoded = object.pop('@binary')
    except KeyError:
        return object
    else:
        return base64.standard_b64decode(encoded)


def safe_kwargs(func, args):
    params = inspect.signature(func).parameters
    return {name: args[name] for name, arg in params.items()
                if arg.kind is arg.KEYWORD_ONLY and name in args}


def make_parser(cls):
    """ Create an ArgumentParser instance based on the keyword-only
        arguments of `cls`'s constructor """
    parser = argparse.ArgumentParser(parents=[common_parser])
    params = inspect.signature(cls).parameters

    for name, arg in params.items():
        # Take just keyword-only arguments
        if arg.kind is not arg.KEYWORD_ONLY:
            continue
        default = arg.default if arg.default is not arg.empty else None
        # TODO: Consider annotations? Will inspect module eval them in Python 4.0?
        _type = type(default) if default is not None else None
        parser.add_argument(f'--{name}', required=arg.default is arg.empty,
                        default=default, type=_type)

    return parser


def require_auth(func):
    """ If a decorated backend method (async or plain) raises AuthRequired,
        indicating that the backend authorization is no longer valid,
        the decorator will call authenticate to refresh it """
    # TODO: logging?
    if inspect.iscoroutinefunction(func):
        async def wrapper(self, *a, **ka):
            try:
                self._async_auth_lock
            except AttributeError:
                self._async_auth_lock = asyncio.Lock()

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
                self._auth_lock = threading.Lock()

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


class DefaultNamespace(SimpleNamespace):
    def __getattr__(self, attr):
        return None
