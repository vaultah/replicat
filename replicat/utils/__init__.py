import ast
import asyncio
import base64
import collections.abc
import functools
import gc
import importlib
import inspect
import logging
import re
import threading
import time
import weakref
from decimal import Decimal
from enum import Enum, auto
from types import SimpleNamespace
from typing import Any, List, Optional

from tqdm import tqdm

from .. import __version__  # noqa
from .. import exceptions

logger = logging.getLogger(__name__)

PREFIXES_TABLE = {
    'k': 1_000,
    'K': 1_000,
    'Ki': 1_024,
    'ki': 1_024,
    'M': 1_000**2,
    'm': 1_000**2,
    'Mi': 1_024**2,
    'mi': 1_024**2,
    'g': 1_000**3,
    'G': 1_000**3,
    'gi': 1_024**3,
    'Gi': 1_024**3,
}
UNITS_TABLE = {'B': 1, 'b': Decimal('0.125')}
HUMAN_SIZE_REGEX = (
    r'(?P<value>([\d]*[.])?[\d]+)\s*?(?P<prefix>%s)?(?P<unit>[Bb])?'
    % "|".join(PREFIXES_TABLE)
)


class AutoLowerStrEnum(str, Enum):
    @staticmethod
    def _generate_next_value_(name, start, count, last_values):
        return name.lower()


class ColumnMixin:
    @classmethod
    def parse_list(cls, string):
        return [cls(x.strip()) for x in string.split(',')]


class SnapshotListColumn(ColumnMixin, AutoLowerStrEnum):
    NAME = auto()
    NOTE = auto()
    TIMESTAMP = auto()
    FILE_COUNT = auto()
    SIZE = auto()


class FileListColumn(ColumnMixin, AutoLowerStrEnum):
    SNAPSHOT_NAME = auto()
    SNAPSHOT_DATE = auto()
    PATH = auto()
    CHUNK_COUNT = auto()
    SIZE = auto()
    DIGEST = auto()
    ATIME = auto()
    MTIME = auto()
    CTIME = auto()


def parse_repository(uri):
    parts = uri.split(':', 1)
    if len(parts) < 2:
        name, connection_string = 'local', parts[0]
    else:
        name, connection_string = parts

    if not name.isidentifier():
        logger.error('Invalid backend module name format')
        raise ValueError

    return name, connection_string


def load_backend(name, connection_string):
    try:
        mod = importlib.import_module(f'..backends.{name}', package=__package__)
    except BaseException as e:
        if not isinstance(e, ModuleNotFoundError):
            logger.exception('Error loading module %s', name)
        raise
    else:
        return (mod.Client, connection_string)


def combine_regexes(regex_list: List[str]) -> str:
    return '|'.join(regex_list)


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


def bytes_to_human(value, prec=2):
    if value < 1_000:
        divisor, unit = 1, 'B'
    elif 1_000 <= value < 1_000**2:
        divisor, unit = 1_000, 'K'
    elif 1_000**2 <= value < 1_000**3:
        divisor, unit = 1_000**2, 'M'
    else:
        divisor, unit = 1_000**3, 'G'

    return f'{round(value / divisor, prec):g}{unit}'


def guess_type(value: str) -> Any:
    if value.lower() in {'none', 'false', 'true'}:
        value = value.title()

    try:
        return ast.literal_eval(value)
    except (ValueError, SyntaxError):
        return value


def flat_to_nested(flat, *, sep='.'):
    """Convert a flat mapping to the equivalent nested/hierarchical
    mapping by splitting keys by the separator"""
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
    """Gets called for objects that can't normally be serialized in JSON.
    We only expect to deal with byte strings right now"""
    # TODO: add memoryview?
    if isinstance(object, collections.abc.ByteString):
        return {'!b': str(base64.standard_b64encode(object), 'ascii')}
    raise TypeError


def type_reverse(object):
    """Intended to be used as an object_hook. Converts the JSON object
    returned from type_hint to a Python object of appropriate type"""
    if len(object) != 1:
        return object

    try:
        encoded = object['!b']
    except KeyError:
        return object
    else:
        return base64.standard_b64decode(encoded)


_async_auth_glock = asyncio.Lock()
_async_auth_locks = weakref.WeakKeyDictionary()
_sync_auth_glock = threading.Lock()
_sync_auth_locks = weakref.WeakKeyDictionary()


def requires_auth(func):
    """If a decorated backend method (async or plain) raises AuthRequired,
    indicating that the backend authorization is no longer valid,
    the decorator will call authenticate to refresh it"""
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


def disable_gc(func):
    def _decorator(*args, **kwargs):
        gcond = gc.isenabled()
        gc.disable()
        try:
            return func(*args, **kwargs)
        finally:
            if gcond:
                gc.enable()

    return _decorator


class DefaultNamespace(SimpleNamespace):
    def __getattr__(self, attr):
        return None


class RateLimiter:
    def __init__(self, limit):
        self.lock = threading.Lock()
        self.limit = limit
        self.checkpoint = None
        self.bytes_since_checkpoint = None

    def available(self):
        with self.lock:
            checkpoint = int(time.monotonic())
            if self.checkpoint is None or self.checkpoint < checkpoint:
                self.bytes_since_checkpoint = 0
                self.checkpoint = checkpoint

            return self.limit - self.bytes_since_checkpoint

    def consumed(self, bytes_amount):
        with self.lock:
            checkpoint = int(time.monotonic())
            if self.checkpoint is None or self.checkpoint < checkpoint:
                self.bytes_since_checkpoint = bytes_amount
                self.checkpoint = checkpoint
            else:
                self.bytes_since_checkpoint += bytes_amount


class TQDMIOReader:
    def __init__(
        self,
        stream,
        *,
        desc,
        total,
        position,
        disable,
        rate_limiter: Optional[RateLimiter] = None,
    ):
        self._stream = stream
        self._rate_limiter = rate_limiter
        self._tracker = tqdm(
            desc=desc,
            unit='B',
            total=total,
            unit_scale=True,
            position=position,
            disable=disable,
            leave=False,
        )

    def read(self, size):
        if self._rate_limiter is not None:
            size = min(max(self._rate_limiter.available(), 1), size, 16_384)
            data = self._stream.read(size)
            self._rate_limiter.consumed(len(data))
        else:
            data = self._stream.read(size)

        self._tracker.update(len(data))
        return data

    def seek(self, *args, **kwargs):
        pos = self._stream.seek(*args, **kwargs)
        self._tracker.reset()
        self._tracker.update(pos)

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self._tracker.close()


class TQDMIOWriter:
    def __init__(
        self,
        stream,
        *,
        desc,
        total,
        position,
        disable,
        rate_limiter: Optional[RateLimiter] = None,
    ):
        self._stream = stream
        self._rate_limiter = rate_limiter
        self._tracker = tqdm(
            desc=desc,
            unit='B',
            total=total,
            unit_scale=True,
            position=position,
            disable=disable,
            leave=False,
        )

    def write(self, data):
        # TODO: rate limiter
        length = self._stream.write(data)
        self._tracker.update(length)
        return length

    def seek(self, *args, **kwargs):
        pos = self._stream.seek(*args, **kwargs)
        self._tracker.reset()
        self._tracker.update(pos)

    def truncate(self, size=None):
        new_size = self._stream.truncate(size)
        self._tracker.reset(new_size)
        return new_size

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self._tracker.close()


async def async_gen_wrapper(it):
    # Probably sufficient for now
    for value in it:
        yield value
        await asyncio.sleep(0)


def iter_chunks(file, chunk_size=128_000):
    return iter(lambda: file.read(chunk_size), b'')


async def aiter_chunks(file, chunk_size=128_000):
    async for chunk in async_gen_wrapper(iter_chunks(file, chunk_size=chunk_size)):
        yield chunk


async def as_completed(tasks):
    queue = asyncio.Queue()

    for task in tasks:
        task.add_done_callback(queue.put_nowait)

    for _ in tasks:
        yield await queue.get()
