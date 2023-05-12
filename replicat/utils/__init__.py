from __future__ import annotations

import ast
import asyncio
import base64
import collections.abc
import functools
import gc
import importlib
import inspect
import io
import logging
import re
import threading
import time
import weakref
from decimal import Decimal
from enum import Enum, auto
from types import SimpleNamespace
from typing import Any, List

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


class _RateLimitedFileWrapper(io.IOBase):
    def __init__(self, file, rate_limiter):
        self._file, self._rate_limiter = file, rate_limiter

    def read(self, size=-1):
        start = time.perf_counter()
        data = self._file.read(size)
        real_elapsed = time.perf_counter() - start
        expected_elapsed = len(data) / self._rate_limiter.read_limit
        self._rate_limiter.pause_reads(max(expected_elapsed - real_elapsed, 0))
        return data

    def write(self, data):
        start = time.perf_counter()
        bytes_written = self._file.write(data)
        real_elapsed = time.perf_counter() - start
        expected_elapsed = bytes_written / self._rate_limiter.write_limit
        self._rate_limiter.pause_writes(max(expected_elapsed - real_elapsed, 0))
        return bytes_written

    def seek(self, *args, **kwargs):
        return self._file.seek(*args, **kwargs)

    def tell(self, *args, **kwargs):
        return self._file.tell(*args, **kwargs)

    def truncate(self, *args, **kwargs):
        return self._file.truncate(*args, **kwargs)

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        super().close()


class RateLimitedIO:
    PAUSE_THRESHOLD_SECONDS = 0.25
    PAUSE_LIMIT = 0.5

    def __init__(self, limit, write_limit=None):
        if write_limit is None:
            write_limit = limit

        self.read_limit = limit
        self.write_limit = write_limit

        self._read_sleep_amortised = 0
        self._read_lock = threading.Lock()
        self._write_sleep_amortised = 0
        self._write_lock = threading.Lock()

    def pause_reads(self, seconds):
        with self._read_lock:
            self._read_sleep_amortised += seconds
            if self._read_sleep_amortised > self.PAUSE_LIMIT:
                self._read_sleep_amortised = self.PAUSE_LIMIT

            if self._read_sleep_amortised <= self.PAUSE_THRESHOLD_SECONDS:
                return

            sleep_start = time.perf_counter()
            time.sleep(self._read_sleep_amortised)
            self._read_sleep_amortised -= time.perf_counter() - sleep_start

    def pause_writes(self, seconds):
        with self._write_lock:
            self._write_sleep_amortised += seconds
            if self._write_sleep_amortised > self.PAUSE_LIMIT:
                self._write_sleep_amortised = self.PAUSE_LIMIT

            if self._write_sleep_amortised <= self.PAUSE_THRESHOLD_SECONDS:
                return

            sleep_start = time.perf_counter()
            time.sleep(self._write_sleep_amortised)
            self._write_sleep_amortised -= time.perf_counter() - sleep_start

    def wrap(self, file):
        return _RateLimitedFileWrapper(file, self)


class TQDMIOBase:
    def __init__(
        self,
        stream,
        *,
        desc,
        total,
        position,
        disable,
    ):
        self._stream = stream
        self._tracker = tqdm(
            desc=desc,
            unit='B',
            total=total,
            unit_scale=True,
            position=position,
            disable=disable,
            leave=False,
        )

    def seek(self, *args, **kwargs):
        pos = self._stream.seek(*args, **kwargs)
        self._tracker.reset()
        self._tracker.update(pos)
        return pos

    def truncate(self, size=None):
        new_size = self._stream.truncate(size)
        self._tracker.reset(new_size)
        return new_size

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self._tracker.close()


class TQDMIOReader(TQDMIOBase):
    def read(self, size=-1):
        data = self._stream.read(size)
        self._tracker.update(len(data))
        return data


class TQDMIOWriter(TQDMIOBase):
    def write(self, data):
        length = self._stream.write(data)
        self._tracker.update(length)
        return length


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
