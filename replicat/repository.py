from __future__ import annotations

import asyncio
import bisect
import collections.abc
import concurrent.futures
import dataclasses
import inspect
import io
import json
import logging
import os
import os.path
import posixpath
import queue
import re
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from decimal import Decimal
from functools import cached_property
from pathlib import Path
from typing import Any, ByteString, Dict, Iterator, List, NamedTuple, Optional, Tuple

from sty import ef, fg
from tqdm import tqdm
from tqdm.utils import CallbackIOWrapper

from . import exceptions, utils
from .backends.base import DEFAULT_STREAM_CHUNK_SIZE
from .utils import FileListColumn, SnapshotListColumn, adapters
from .utils.compat import Random
from .utils.config import DEFAULT_CACHE_DIRECTORY
from .utils.fs import flatten_paths

logger = logging.getLogger(__name__)

_queue_timeout = 0.025  # seconds


class LocationParts(NamedTuple):
    name: str
    tag: str


# dataclasses are hilariously slow when all you need is an
# immutable typed thing with __init__ and attribute access
class _SnapshotChunk(NamedTuple):
    contents: bytes
    table_index: int
    location: str
    stream_start: int
    stream_end: int
    counter: int


@dataclasses.dataclass
class _SnapshotFile:
    path: str
    stream_start: int
    stream_end: int
    metadata: Optional[Dict[str, Any]] = None
    digest: Optional[bytes] = None


@dataclasses.dataclass
class _SnapshotState:
    bytes_with_padding: int = 0
    bytes_chunked: int = 0
    bytes_reused: int = 0
    chunk_counter: int = 0
    current_file: Optional[_SnapshotFile] = None
    files: List[Tuple[int, _SnapshotFile]] = dataclasses.field(default_factory=list)


@dataclasses.dataclass(repr=False, frozen=True)
class RepositoryProps:
    chunker: adapters.ChunkerAdapter
    hasher: adapters.HashAdapter
    cipher: Optional[adapters.CipherAdapter] = None
    userkey: Optional[bytes] = None
    authenticator: Optional[adapters.MACAdapter] = None
    shared_kdf: Optional[adapters.KDFAdapter] = None
    private: Optional[Dict[str, Any]] = None

    @cached_property
    def encrypted(self) -> bool:
        return self.cipher is not None

    def hash_digest(self, data: bytes) -> bytes:
        return self.hasher.digest(data)

    def incremental_hasher(self) -> adapters.IncrementalHasher:
        return self.hasher.incremental_hasher()

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        assert self.encrypted
        assert self.cipher is not None
        return self.cipher.encrypt(data, key)

    def decrypt(self, data: bytes, key: bytes) -> bytes:
        assert self.encrypted
        assert self.cipher is not None
        return self.cipher.decrypt(data, key)

    def mac(self, data: bytes) -> bytes:
        assert self.encrypted
        assert self.authenticator is not None
        assert self.private is not None
        return self.authenticator.mac(data, params=self.private['mac_params'])

    def derive_shared_subkey(self, ctx: bytes) -> bytes:
        assert self.encrypted
        assert self.shared_kdf is not None
        assert self.private is not None
        return self.shared_kdf.derive(
            self.private['shared_key'],
            context=ctx,
            params=self.private['shared_kdf_params'],
        )

    def chunkify(self, it: Iterator[ByteString]) -> Iterator[bytes]:
        if self.encrypted:
            assert self.private is not None
            params = self.private['chunker_params']
        else:
            params = None

        return self.chunker(it, params=params)


class Repository:
    # NOTE: trailing slashes
    CHUNK_PREFIX = 'data/'
    SNAPSHOT_PREFIX = 'snapshots/'
    # These correspond to the names of adapters
    DEFAULT_CHUNKER_NAME = 'gclmulchunker'
    DEFAULT_CIPHER_NAME = 'aes_gcm'
    DEFAULT_HASHER_NAME = 'blake2b'
    DEFAULT_MAC_NAME = 'blake2b'
    DEFAULT_USER_KDF_NAME = 'scrypt'
    # Fast KDF for high-entropy inputs (used for shared data)
    DEFAULT_SHARED_KDF_NAME = 'blake2b'
    EMPTY_TABLE_VALUE = '--'
    DEFAULT_CACHE_DIRECTORY = DEFAULT_CACHE_DIRECTORY
    SNAPSHOT_LIST_COLUMN_LABELS = {
        SnapshotListColumn.NAME: 'name',
        SnapshotListColumn.NOTE: 'note',
        SnapshotListColumn.TIMESTAMP: 'timestamp (utc)',
        SnapshotListColumn.FILE_COUNT: 'files',
        SnapshotListColumn.SIZE: 'size',
    }
    FILE_LIST_COLUMN_LABELS = {
        FileListColumn.SNAPSHOT_NAME: 'snapshot name',
        FileListColumn.SNAPSHOT_DATE: 'snapshot date',
        FileListColumn.PATH: 'path',
        FileListColumn.CHUNK_COUNT: 'chunks',
        FileListColumn.SIZE: 'size',
        FileListColumn.DIGEST: 'digest',
        FileListColumn.ATIME: 'accessed at',
        FileListColumn.MTIME: 'modified at',
        FileListColumn.CTIME: 'created at',
    }

    def __init__(
        self,
        backend,
        *,
        concurrent,
        quiet=True,
        cache_directory=DEFAULT_CACHE_DIRECTORY,
    ):
        self._concurrent = concurrent
        self._quiet = quiet
        self._cache_directory = cache_directory

        self._slots = asyncio.PriorityQueue(maxsize=concurrent)
        # We need actual integers for TQDM slot management in CLI, but this queue
        # can also act as a semaphore in the general case. Note that numbering starts
        # from 2, leaving two topmost slots to non-slotable trackers
        for slot in range(2, concurrent + 2):
            self._slots.put_nowait(slot)

        self.backend = backend

    def display_status(self, message):
        print(ef.bold + message + ef.rs, file=sys.stderr)

    def display_warning(self, message):
        print(fg(242, 200, 15) + ef.bold + message + ef.rs + fg.rs, file=sys.stderr)

    def display_danger(self, message):
        print(fg(255, 10, 10) + ef.bold + message + ef.rs + fg.rs, file=sys.stderr)

    def _get_cached(self, path):
        assert self._cache_directory is not None
        return Path(self._cache_directory, path).read_bytes()

    def _store_cached(self, path, data):
        assert self._cache_directory is not None
        file = Path(self._cache_directory, path)
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(data)

    def _delete_cached(self, path):
        assert self._cache_directory is not None
        return Path(self._cache_directory, path).unlink(missing_ok=True)

    @property
    def _unlocked(self):
        return hasattr(self, 'props')

    @cached_property
    def _default_backend_executor(self):
        """Default executor for non-async methods of the backend instance"""
        return ThreadPoolExecutor(
            max_workers=self._concurrent, thread_name_prefix='default-backend-executor'
        )

    @asynccontextmanager
    async def _acquire_slot(self):
        slot = await self._slots.get()
        try:
            yield slot
        finally:
            self._slots.put_nowait(slot)

    @contextmanager
    def _acquire_slot_threadsafe(self, *, loop):
        slot = asyncio.run_coroutine_threadsafe(self._slots.get(), loop).result()
        try:
            yield slot
        finally:
            loop.call_soon_threadsafe(self._slots.put_nowait, slot)

    async def _maybe_run_in_executor(self, func, *args, executor=None, **kwargs):
        if inspect.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        else:
            loop = asyncio.get_running_loop()
            if executor is None:
                executor = self._default_backend_executor
            return await loop.run_in_executor(executor, func, *args, **kwargs)

    def _maybe_run_coroutine_threadsafe(self, func, *args, loop, **kwargs):
        if inspect.iscoroutinefunction(func):
            return asyncio.run_coroutine_threadsafe(
                func(*args, **kwargs), loop
            ).result()
        else:
            return func(*args, **kwargs)

    # Convenience wrappers for backend methods that do not need to know
    # the actual slot they are occupying (so most of them)
    async def _exists(self, location, /, *, executor=None):
        async with self._acquire_slot():
            logger.info('Checking existence of %s', location)
            return await self._maybe_run_in_executor(
                self.backend.exists, location, executor=executor
            )

    def _exists_threadsafe(self, location, /, *, loop):
        with self._acquire_slot_threadsafe(loop=loop):
            logger.info('Checking existence of %s', location)
            return self._maybe_run_coroutine_threadsafe(
                self.backend.exists, location, loop=loop
            )

    async def _download(self, location, /, *, executor=None):
        async with self._acquire_slot():
            logger.info('Downloading %s', location)
            return await self._maybe_run_in_executor(
                self.backend.download, location, executor=executor
            )

    def _download_threadsafe(self, location, /, *, loop):
        with self._acquire_slot_threadsafe(loop=loop):
            logger.info('Downloading %s', location)
            return self._maybe_run_coroutine_threadsafe(
                self.backend.download, location, loop=loop
            )

    async def _upload_data(self, location, data, /, *, executor=None):
        async with self._acquire_slot():
            logger.info('Uploading binary data (%d bytes) to %s', len(data), location)
            return await self._maybe_run_in_executor(
                self.backend.upload, location, data, executor=executor
            )

    def _upload_data_threadsafe(self, location, data, /, *, loop):
        with self._acquire_slot_threadsafe(loop=loop):
            logger.info('Uploading binary data (%d bytes) to %s', len(data), location)
            return self._maybe_run_coroutine_threadsafe(
                self.backend.upload, location, data, loop=loop
            )

    async def _delete(self, location, /, *, executor=None):
        async with self._acquire_slot():
            logger.info('Deleting %s', location)
            return await self._maybe_run_in_executor(
                self.backend.delete, location, executor=executor
            )

    def _delete_threadsafe(self, location, /, *, loop):
        with self._acquire_slot_threadsafe(loop=loop):
            logger.info('Deleting %s', location)
            return self._maybe_run_coroutine_threadsafe(
                self.backend.delete, location, loop=loop
            )

    async def _clean(self, /, *, executor=None):
        async with self._acquire_slot():
            logger.info('Running backend clean-up')
            return await self._maybe_run_in_executor(
                self.backend.clean, executor=executor
            )

    def _clean_threadsafe(self, /, *, loop):
        with self._acquire_slot_threadsafe(loop=loop):
            logger.info('Running backend clean-up')
            return self._maybe_run_coroutine_threadsafe(self.backend.clean, loop=loop)

    async def _close(self, /, *, executor=None):
        async with self._acquire_slot():
            logger.info('Closing backend instance')
            return await self._maybe_run_in_executor(
                self.backend.close, executor=executor
            )

    def _close_threadsafe(self, /, *, loop):
        with self._acquire_slot_threadsafe(loop=loop):
            logger.info('Closing backend instance')
            return self._maybe_run_coroutine_threadsafe(self.backend.close, loop=loop)

    async def _aiter(self, func, *args, **kwargs):
        if inspect.isasyncgenfunction(func):
            result = func(*args, **kwargs)
        else:
            result = await self._maybe_run_in_executor(func, *args, **kwargs)

        if not isinstance(result, collections.abc.AsyncIterable):
            result = utils.async_gen_wrapper(result)

        async for value in result:
            yield value

    def _compile_or_none(self, pattern):
        return re.compile(pattern) if pattern is not None else None

    def default_serialization_hook(self, data, /):
        return utils.type_hint(data)

    def serialize(self, object, /):
        string = json.dumps(
            object, separators=(',', ':'), default=self.default_serialization_hook
        )
        return bytes(string, 'ascii')

    def object_deserialization_hook(self, data, /):
        return utils.type_reverse(data)

    def deserialize(self, data, /):
        return json.loads(data, object_hook=self.object_deserialization_hook)

    def get_chunk_location(self, *, name, tag):
        """Build POSIX-style storage path for the chunk using its name and tag.
        The tag is included for ownership verification. The part after the last slash
        (actual filename on the filesystem) must be under 255 bytes for compatibility
        with most filesystems. You can assume that both name and tag are hex-strings
        each no longer than 128 characters. The returned path must start with
        CHUNK_PREFIX and is allowed to contain forward slashes, characters from name
        and tag, and hyphens."""
        return posixpath.join(
            self.CHUNK_PREFIX,
            tag[:2],
            tag[2:4],
            f'{tag[4:]}-{name}',
        )

    def parse_chunk_location(self, location, /):
        """Parse the storage path for the chunk, extract its name and tag"""
        if not location.startswith(self.CHUNK_PREFIX):
            raise ValueError('Not a chunk location')

        head, _, name = location.rpartition('-')
        parts = head.rsplit('/', 3)
        return LocationParts(name=name, tag=parts[1] + parts[2] + parts[3])

    def _chunk_digest_to_location_parts(self, digest, /):
        if self.props.encrypted:
            digest_mac = self.props.mac(digest)
            digest_mac_mac = self.props.mac(digest_mac)
        else:
            digest_mac = digest_mac_mac = digest

        return LocationParts(name=digest_mac.hex(), tag=digest_mac_mac.hex())

    def _chunk_digest_to_location(self, digest):
        name, tag = self._chunk_digest_to_location_parts(digest)
        return self.get_chunk_location(name=name, tag=tag)

    def get_snapshot_location(self, *, name, tag):
        """Build POSIX-style storage path for the snapshot using its name and tag.
        The tag is included for ownership verification. The part after the last slash
        (actual filename on the filesystem) must be under 255 bytes for compatibility
        with most filesystems. You can assume that both name and tag are hex-strings
        each no longer than 128 characters. The returned path must start with
        SNAPSHOT_PREFIX and is allowed to contain forward slashes, characters from name
        and tag, and hyphens."""
        return posixpath.join(self.SNAPSHOT_PREFIX, tag[:2], f'{tag[2:]}-{name}')

    def parse_snapshot_location(self, location, /):
        """Parse the storage path for the snapshot, extract its name and tag"""
        if not location.startswith(self.SNAPSHOT_PREFIX):
            raise ValueError('Not a snapshot location')
        head, _, name = location.rpartition('-')
        parts = head.rsplit('/', 2)
        return LocationParts(name=name, tag=parts[1] + parts[2])

    def _snapshot_digest_to_location_parts(self, digest, /):
        digest_mac = self.props.mac(digest) if self.props.encrypted else digest
        return LocationParts(name=digest.hex(), tag=digest_mac.hex())

    def read_metadata(self, file):
        if isinstance(file, int):
            stat_result = os.fstat(file)
        else:
            stat_result = os.stat(file)

        return {
            'st_mode': stat_result.st_mode,
            'st_uid': stat_result.st_uid,
            'st_gid': stat_result.st_gid,
            'st_size': stat_result.st_size,
            'st_atime_ns': stat_result.st_atime_ns,
            'st_mtime_ns': stat_result.st_mtime_ns,
            'st_ctime_ns': stat_result.st_ctime_ns,
        }

    def restore_metadata(self, path, metadata, /):
        # NOTE: fall back to non-nanosecond timestamps for compatibility with snapshots
        # that were created by older replicat versions (pre-1.3)
        try:
            ns = (metadata['st_atime_ns'], metadata['st_mtime_ns'])
        except KeyError:
            os.utime(path, times=(metadata['st_atime'], metadata['st_mtime']))
        else:
            os.utime(path, ns=ns)

    def _validate_settings(self, schema, obj):
        extra_keys = obj.keys() - schema.keys()
        if extra_keys:
            raise exceptions.ReplicatError(
                'Settings include unrecognized properties: '
                + ', '.join(map(repr, extra_keys))
            )

        for key, value in obj.items():
            allowed_types = schema[key]
            if isinstance(value, allowed_types):
                continue

            if isinstance(allowed_types, tuple):
                type_names = ', '.join([x.__name__ for x in allowed_types])
            else:
                type_names = allowed_types.__name__

            raise exceptions.ReplicatError(
                f'{key!r} -> {value!r} does not match any '
                f'of the allowed types ({type_names})'
            )

    def _make_config(self, *, settings=None):
        if settings is None:
            settings = {}

        config = {}

        # Hashing
        hashing_settings = settings.get('hashing', {})
        hashing_settings.setdefault('name', self.DEFAULT_HASHER_NAME)
        hasher_type, hasher_args = adapters.from_config(**hashing_settings)
        config['hashing'] = dict(hasher_args, name=hasher_type.__name__)

        # Deduplication params
        chunking_settings = settings.get('chunking', {})
        chunking_settings.setdefault('name', self.DEFAULT_CHUNKER_NAME)
        chunker_type, chunker_args = adapters.from_config(**chunking_settings)
        config['chunking'] = dict(chunker_args, name=chunker_type.__name__)

        if (encryption_settings := settings.get('encryption', {})) is not None:
            cipher_settings = encryption_settings.get('cipher', {})
            cipher_settings.setdefault('name', self.DEFAULT_CIPHER_NAME)
            cipher_type, cipher_args = adapters.from_config(**cipher_settings)
            config['encryption'] = {
                'cipher': dict(cipher_args, name=cipher_type.__name__)
            }

        return config

    def _instantiate_config(self, config):
        chunker_type, chunker_args = adapters.from_config(**config['chunking'])
        hasher_type, hasher_args = adapters.from_config(**config['hashing'])

        if (encryption_config := config.get('encryption')) is not None:
            cipher_type, cipher_args = adapters.from_config(
                **encryption_config['cipher']
            )
            cipher = cipher_type(**cipher_args)
        else:
            cipher = None

        return {
            'chunker': chunker_type(**chunker_args),
            'hasher': hasher_type(**hasher_args),
            'cipher': cipher,
        }

    def _make_private(self, *, cipher, chunker, settings=None):
        if settings is None:
            settings = {}

        encryption_settings = settings.get('encryption', {})
        shared_kdf_settings = encryption_settings.get('shared_kdf', {})
        shared_kdf_settings.setdefault('name', self.DEFAULT_SHARED_KDF_NAME)
        shared_kdf_type, shared_args = adapters.from_config(
            **shared_kdf_settings, length=cipher.key_bytes
        )
        shared_kdf = shared_kdf_type(**shared_args)

        # Message authentication
        mac_settings = encryption_settings.get('mac', {})
        mac_settings.setdefault('name', self.DEFAULT_MAC_NAME)
        mac_type, mac_args = adapters.from_config(**mac_settings)
        mac = mac_type(**mac_args)

        return {
            'shared_key': cipher.generate_key(),
            'shared_kdf': dict(shared_args, name=shared_kdf_type.__name__),
            'shared_kdf_params': shared_kdf.generate_derivation_params(),
            'mac': dict(mac_args, name=mac_type.__name__),
            'mac_params': mac.generate_mac_params(),
            'chunker_params': chunker.generate_chunking_params(),
        }

    def _make_encrypted_key(self, *, cipher, private, settings=None):
        if settings is None:
            settings = {}

        encryption_settings = settings.get('encryption', {})
        # KDF for user personal data
        user_kdf_settings = encryption_settings.get('kdf', {})
        user_kdf_settings.setdefault('name', self.DEFAULT_USER_KDF_NAME)
        user_kdf_type, user_kdf_args = adapters.from_config(
            **user_kdf_settings, length=cipher.key_bytes
        )
        user_kdf = user_kdf_type(**user_kdf_args)

        return {
            'kdf': dict(user_kdf_args, name=user_kdf_type.__name__),
            'kdf_params': user_kdf.generate_derivation_params(),
            'private': private,
        }

    def _make_unencrypted_key(self, *, cipher, private, settings=None):
        return {'userkey': cipher.generate_key(), 'private': private}

    def _is_key_encrypted(self, key):
        return 'userkey' not in key

    def _instantiate_unencrypted_key(self, key):
        userkey, private = key['userkey'], key['private']
        # Message authentication
        authenticator_type, authenticator_args = adapters.from_config(**private['mac'])
        # KDF for shared data
        shared_kdf_type, shared_kdf_args = adapters.from_config(**private['shared_kdf'])
        return {
            'userkey': userkey,
            'private': private,
            'authenticator': authenticator_type(**authenticator_args),
            'shared_kdf': shared_kdf_type(**shared_kdf_args),
        }

    def _instantiate_encrypted_key(self, key, *, password, cipher):
        kdf_type, kdf_args = adapters.from_config(**key['kdf'])
        userkey = kdf_type(**kdf_args).derive(password, params=key['kdf_params'])

        if isinstance(key['private'], bytes):
            # The 'private' portion of the key is still encrypted
            private = self.deserialize(cipher.decrypt(key['private'], userkey))
        else:
            private = key['private']

        # Message authentication
        authenticator_type, authenticator_args = adapters.from_config(**private['mac'])
        # KDF for shared data
        shared_kdf_type, shared_kdf_args = adapters.from_config(**private['shared_kdf'])
        return {
            'userkey': userkey,
            'private': private,
            'authenticator': authenticator_type(**authenticator_args),
            'shared_kdf': shared_kdf_type(**shared_kdf_args),
        }

    def _validate_init_settings(self, settings):
        self._validate_settings(
            {
                'hashing': collections.abc.Mapping,
                'chunking': collections.abc.Mapping,
                'encryption': (collections.abc.Mapping, type(None)),
            },
            settings,
        )

        if (encryption_settings := settings.get('encryption')) is not None:
            self._validate_settings(
                {
                    'cipher': collections.abc.Mapping,
                    'kdf': collections.abc.Mapping,
                },
                encryption_settings,
            )

    async def init(self, *, password=None, settings=None, key_output_path=None):
        if settings:
            self._validate_init_settings(settings)

        logger.info('Using provided settings: %r', settings)
        self.display_status('Generating new config')
        config = self._make_config(settings=settings)
        print(json.dumps(config, indent=4, default=self.default_serialization_hook))
        props = RepositoryProps(**self._instantiate_config(config))

        if props.encrypted:
            self.display_status('Generating new key')
            private = self._make_private(
                cipher=props.cipher, chunker=props.chunker, settings=settings
            )
            logger.debug('Private key portion (unencrypted): %r', private)

            if password is None:
                self.display_warning(
                    'Password was not provided, so the key will NOT be encrypted. '
                    'Make sure to store it securely.'
                )
                key = self._make_unencrypted_key(
                    cipher=props.cipher, settings=settings, private=private
                )
                props = dataclasses.replace(
                    props,
                    **self._instantiate_unencrypted_key(key),
                )
            else:
                key = self._make_encrypted_key(
                    cipher=props.cipher, settings=settings, private=private
                )
                props = dataclasses.replace(
                    props,
                    **self._instantiate_encrypted_key(
                        key, password=password, cipher=props.cipher
                    ),
                )
                # Encrypt the private portion
                key['private'] = props.encrypt(
                    self.serialize(key['private']), props.userkey
                )

            # TODO: store keys in the repository?
            if key_output_path is not None:
                key_output_path = Path(key_output_path).resolve()
                self.display_status(f'Writing key to {key_output_path}')
                key_output_path.write_bytes(self.serialize(key))
            else:
                print(
                    json.dumps(key, indent=4, default=self.default_serialization_hook)
                )
        else:
            key = None

        self.display_status('Uploading config')
        await self._upload_data('config', self.serialize(config))

        self.props = props
        return utils.DefaultNamespace(config=config, key=key)

    def _parse_config(self, contents):
        return RepositoryProps(**self._instantiate_config(self.deserialize(contents)))

    async def unlock(self, *, password=None, key=None):
        self.display_status('Loading config')
        props = self._parse_config(await self._download('config'))

        if props.encrypted:
            self.display_status('Unlocking repository')

            if key is None:
                raise exceptions.ReplicatError(
                    'Key is required to unlock this repository'
                )

            # TODO: Load keys from the backend as a fallback?
            if isinstance(key, (str, collections.abc.ByteString)):
                key = self.deserialize(key)

            if self._is_key_encrypted(key):
                if password is None:
                    raise exceptions.ReplicatError(
                        'Both password and key are needed to unlock this repository'
                    )

                props = dataclasses.replace(
                    props,
                    **self._instantiate_encrypted_key(
                        key, password=password, cipher=props.cipher
                    ),
                )
            else:
                props = dataclasses.replace(
                    props,
                    **self._instantiate_uencrypted_key(
                        key, password=password, cipher=props.cipher
                    ),
                )

        self.props = props

    def _validate_add_key_settings(self, settings):
        self._validate_settings(
            {'encryption': collections.abc.Mapping},
            settings,
        )
        self._validate_settings(
            {'kdf': collections.abc.Mapping},
            settings['encryption'],
        )

    async def add_key(
        self, *, password, settings=None, shared=False, key_output_path=None
    ):
        if settings:
            self._validate_add_key_settings(settings)

        logger.info('Using provided settings: %r', settings)

        if shared:
            if not self._unlocked:
                raise exceptions.ReplicatError('The repository must be unlocked')
            private = self.props.private
            props = self.props
        else:
            private = None
            if self._unlocked:
                props = self.props
            else:
                self.display_status('Loading config')
                props = self._parse_config(await self._download('config'))

        if not props.encrypted:
            raise exceptions.ReplicatError('Repository is not encrypted')

        if private is None:
            private = self._make_private(
                cipher=props.cipher, chunker=props.chunker, settings=settings
            )

        self.display_status('Generating new key')
        logger.debug('Private key portion of the new key (unencrypted): %r', private)

        if password is None:
            self.display_warning(
                'Password was not provided, so the key will NOT be encrypted. '
                'Make sure to store it securely.'
            )
            key = self._make_unencrypted_key(
                cipher=props.cipher, settings=settings, private=private
            )
        else:
            key = self._make_encrypted_key(
                cipher=props.cipher, settings=settings, private=private
            )

            props = dataclasses.replace(
                props,
                **self._instantiate_encrypted_key(
                    key, password=password, cipher=props.cipher
                ),
            )
            # Encrypt the private portion
            key['private'] = props.encrypt(
                self.serialize(key['private']),
                props.userkey,
            )

        # TODO: store it in the repository?
        if key_output_path is not None:
            key_output_path = Path(key_output_path).resolve()
            self.display_status(f'Writing key to {key_output_path}')
            key_output_path.write_bytes(self.serialize(key))
        else:
            print(json.dumps(key, indent=4, default=self.default_serialization_hook))

        return utils.DefaultNamespace(new_key=key)

    def _encrypt_snapshot_body(self, snapshot_body):
        if self.props.encrypted:
            encrypted_private_data = self.props.encrypt(
                self.serialize(snapshot_body['data']), self.props.userkey
            )
            encrypted_body = {
                'chunks': self.props.encrypt(
                    self.serialize(snapshot_body['chunks']),
                    self.props.derive_shared_subkey(
                        self.props.hash_digest(encrypted_private_data)
                    ),
                ),
                'data': encrypted_private_data,
            }
        else:
            encrypted_body = snapshot_body

        return self.serialize(encrypted_body)

    def _decrypt_snapshot_body(self, contents):
        body = self.deserialize(contents)

        if self.props.encrypted:
            body['chunks'] = self.deserialize(
                self.props.decrypt(
                    body['chunks'],
                    self.props.derive_shared_subkey(
                        self.props.hash_digest(body['data'])
                    ),
                )
            )
            try:
                data = self.props.decrypt(body['data'], self.props.userkey)
            except exceptions.DecryptionError:
                body['data'] = None
            else:
                body['data'] = self.deserialize(data)

        return body

    def _download_snapshot_threadsafe(self, path, expected_digest, *, loop):
        contents = None
        if self._cache_directory is not None:
            try:
                contents = self._get_cached(path)
            except FileNotFoundError:
                pass

        if contents is None:
            contents = self._download_threadsafe(path, loop=loop)

            logger.info('Verifying %s', path)
            if self.props.hash_digest(contents) != expected_digest:
                raise exceptions.ReplicatError(f'Snapshot at {path!r} is corrupted')

            if self._cache_directory is not None:
                logger.info('Caching %s', path)
                self._store_cached(path, contents)

        logger.info('Decrypting %s', path)
        body = self._decrypt_snapshot_body(contents)

        if body['data'] is None:
            logger.info(
                "Decryption of %s failed, but it's not corrupted (different key?)",
                path,
            )

        return body

    async def _load_snapshots(self, *, snapshot_regex=None):
        # In the most common case, we'll just load cached files and do some key
        # derivation and decryption, all of which might benefit from use of multiple
        # threads. In case we have to download some snapshots, we can run plain backend
        # methods directly from the threads and submit coroutines to the current event
        # loop. That said, we aren't using the standard backend executor for this, since
        # the second case should be rare, and to avoid potentially blocking unrelated
        # calls, but we still have to use slots to limit concurrent calls to the backend
        loader = ThreadPoolExecutor(
            max_workers=self._concurrent, thread_name_prefix='snapshot-loader'
        )
        future_to_path = {}
        loop = asyncio.get_running_loop()
        snapshot_re = self._compile_or_none(snapshot_regex)

        def _download_snapshot(path):
            name, tag = self.parse_snapshot_location(path)
            if snapshot_re is not None and snapshot_re.search(name) is None:
                logger.info('Skipping %s (does not match the filter)', path)
                return

            digest = bytes.fromhex(name)
            if self.props.encrypted and self.props.mac(digest) != bytes.fromhex(tag):
                logger.info('Skipping %s (invalid tag)', path)
                return

            return self._download_snapshot_threadsafe(path, digest, loop=loop)

        async for path in self._aiter(self.backend.list_files, self.SNAPSHOT_PREFIX):
            future = loop.run_in_executor(loader, _download_snapshot, path)
            future_to_path[future] = path

        async for task in utils.as_completed(future_to_path):
            if (body := await task) is None:
                continue
            yield future_to_path[task], body

    def _extract_snapshot_size(self, snapshot_data):
        files = snapshot_data['files']
        ranges_it = (chunk['range'] for file in files for chunk in file['chunks'])
        return sum(r[1] - r[0] for r in ranges_it)

    def _extract_snapshot_note(self, snapshot_data):
        return snapshot_data.get('note')

    def _extract_snapshot_file_count(self, snapshot_data):
        return len(snapshot_data['files'])

    def _extract_snapshot_utc_timestamp(self, snapshot_data):
        return datetime.fromisoformat(snapshot_data['utc_timestamp'])

    def _format_snapshot_name(self, *, path, chunks, data):
        return self.parse_snapshot_location(path).name

    def _format_snapshot_note(self, *, path, chunks, data):
        return data and self._extract_snapshot_note(data)

    def _format_snapshot_utc_timestamp(self, *, path, chunks, data):
        if data is None:
            return None

        dt = self._extract_snapshot_utc_timestamp(data)
        return dt.isoformat(sep=' ', timespec='seconds')

    def _format_snapshot_file_count(self, *, path, chunks, data):
        return data and self._extract_snapshot_file_count(data)

    def _format_snaphot_size(self, *, path, chunks, data):
        return data and utils.bytes_to_human(self._extract_snapshot_size(data))

    async def list_snapshots(self, *, snapshot_regex=None, header=True, columns=None):
        if columns is None:
            columns = [
                SnapshotListColumn.NAME,
                SnapshotListColumn.NOTE,
                SnapshotListColumn.TIMESTAMP,
                SnapshotListColumn.FILE_COUNT,
                SnapshotListColumn.SIZE,
            ]

        columns_getters = {
            SnapshotListColumn.NAME: self._format_snapshot_name,
            SnapshotListColumn.NOTE: self._format_snapshot_note,
            SnapshotListColumn.TIMESTAMP: self._format_snapshot_utc_timestamp,
            SnapshotListColumn.FILE_COUNT: self._format_snapshot_file_count,
            SnapshotListColumn.SIZE: self._format_snaphot_size,
        }
        columns_widths = {}
        snapshots = []

        self.display_status('Loading snapshots')
        async for snapshot_path, snapshot_body in self._load_snapshots(
            snapshot_regex=snapshot_regex
        ):
            row = {}
            snapshot_chunks = snapshot_body['chunks']
            snapshot_data = snapshot_body['data']

            for column in columns:
                getter = columns_getters[column]
                value = getter(
                    path=snapshot_path,
                    chunks=snapshot_chunks,
                    data=snapshot_data,
                )
                value = str(value if value is not None else self.EMPTY_TABLE_VALUE)
                row[column] = value
                columns_widths[column] = max(len(value), columns_widths.get(column, 0))

            if snapshot_data is not None:
                snapshot_timestamp = snapshot_data['utc_timestamp']
            else:
                snapshot_timestamp = None

            snapshots.append((snapshot_timestamp, row))

        if not snapshots:
            return

        snapshots.sort(key=lambda x: x[0] or '', reverse=True)

        if header:
            formatted_headers = []
            for column, width in columns_widths.items():
                label = self.SNAPSHOT_LIST_COLUMN_LABELS[column]
                width = columns_widths[column] = max(len(label), columns_widths[column])
                formatted_headers.append(label.upper().center(width))

            print(*formatted_headers, sep='\t')

        for _, row in snapshots:
            print(
                *(value.ljust(columns_widths[col]) for col, value in row.items()),
                sep='\t',
            )

    def _format_file_snapshot_name(
        self, *, snapshot_path, snapshot_chunks, snapshot_data, file_data
    ):
        return self.parse_snapshot_location(snapshot_path).name

    def _format_file_snapshot_date(
        self, *, snapshot_path, snapshot_chunks, snapshot_data, file_data
    ):
        dt = datetime.fromisoformat(snapshot_data['utc_timestamp'])
        return dt.isoformat(sep=' ', timespec='seconds')

    def _format_file_path(
        self, *, snapshot_path, snapshot_chunks, snapshot_data, file_data
    ):
        return file_data['path']

    def _format_file_chunk_count(
        self, *, snapshot_path, snapshot_chunks, snapshot_data, file_data
    ):
        return len(file_data['chunks'])

    def _format_file_size(
        self, *, snapshot_path, snapshot_chunks, snapshot_data, file_data
    ):
        ranges_it = (cd['range'] for cd in file_data['chunks'])
        return utils.bytes_to_human(sum(r[1] - r[0] for r in ranges_it))

    def _format_file_digest(
        self, *, snapshot_path, snapshot_chunks, snapshot_data, file_data
    ):
        return (digest := file_data.get('digest')) and digest.hex()

    def _metadata_ts_to_dt(self, metadata, key):
        try:
            ts = metadata[key] / 1e9
        except KeyError:
            # NOTE: fall back to non-nanosecond timestamps for compatibility with
            # snapshots that were created by older replicat versions (pre-1.3)
            assert key.endswith('_ns'), key
            ts = metadata[key[:-3]]

        return datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)

    def _format_file_mtime(
        self, *, snapshot_path, snapshot_chunks, snapshot_data, file_data
    ):
        dt = self._metadata_ts_to_dt(file_data['metadata'], 'st_mtime_ns')
        return dt.isoformat(sep=' ', timespec='seconds')

    def _format_file_ctime(
        self, *, snapshot_path, snapshot_chunks, snapshot_data, file_data
    ):
        dt = self._metadata_ts_to_dt(file_data['metadata'], 'st_ctime_ns')
        return dt.isoformat(sep=' ', timespec='seconds')

    def _format_file_atime(
        self, *, snapshot_path, snapshot_chunks, snapshot_data, file_data
    ):
        dt = self._metadata_ts_to_dt(file_data['metadata'], 'st_atime_ns')
        return dt.isoformat(sep=' ', timespec='seconds')

    async def list_files(
        self, *, snapshot_regex=None, file_regex=None, header=True, columns=None
    ):
        if columns is None:
            columns = [
                FileListColumn.SNAPSHOT_DATE,
                FileListColumn.PATH,
                FileListColumn.CHUNK_COUNT,
                FileListColumn.SIZE,
                FileListColumn.MTIME,
            ]

        columns_getters = {
            FileListColumn.SNAPSHOT_NAME: self._format_file_snapshot_name,
            FileListColumn.SNAPSHOT_DATE: self._format_file_snapshot_date,
            FileListColumn.PATH: self._format_file_path,
            FileListColumn.CHUNK_COUNT: self._format_file_chunk_count,
            FileListColumn.SIZE: self._format_file_size,
            FileListColumn.DIGEST: self._format_file_digest,
            FileListColumn.ATIME: self._format_file_atime,
            FileListColumn.MTIME: self._format_file_mtime,
            FileListColumn.CTIME: self._format_file_ctime,
        }
        columns_widths = {}
        files = []
        file_re = self._compile_or_none(file_regex)

        self.display_status('Loading snapshots')
        async for snapshot_path, snapshot_body in self._load_snapshots(
            snapshot_regex=snapshot_regex
        ):
            snapshot_chunks = snapshot_body['chunks']
            snapshot_data = snapshot_body['data']
            if snapshot_data is None:
                continue

            for file_data in snapshot_data['files']:
                if file_re is not None and file_re.search(file_data['path']) is None:
                    continue

                row = {}
                for column in columns:
                    getter = columns_getters[column]
                    value = getter(
                        snapshot_path=snapshot_path,
                        snapshot_chunks=snapshot_chunks,
                        snapshot_data=snapshot_data,
                        file_data=file_data,
                    )
                    value = str(value if value is not None else self.EMPTY_TABLE_VALUE)
                    row[column] = value
                    columns_widths[column] = max(
                        len(value), columns_widths.get(column, 0)
                    )

                files.append((snapshot_data['utc_timestamp'], row))

        if not files:
            return

        files.sort(key=lambda x: x[0], reverse=True)

        if header:
            formatted_headers = []
            for column, width in columns_widths.items():
                label = self.FILE_LIST_COLUMN_LABELS[column]
                width = columns_widths[column] = max(len(label), columns_widths[column])
                formatted_headers.append(label.upper().center(width))

            print(*formatted_headers, sep='\t')

        for _, row in files:
            print(
                *(value.ljust(columns_widths[col]) for col, value in row.items()),
                sep='\t',
            )

    def _flatten_resolve_paths(self, paths):
        return list(flatten_paths(path.resolve(strict=True) for path in paths))

    async def snapshot(self, *, paths, note=None, rate_limit=None):
        self.display_status('Collecting files')
        files = self._flatten_resolve_paths(paths)
        logger.info('Found %d files', len(files))
        # Small files are more likely to change than big files, read them quickly
        # and bundle them together
        files.sort(key=lambda file: (file.stat().st_size, str(file)))

        loop = asyncio.get_running_loop()
        chunk_queue = queue.Queue(maxsize=self._concurrent * 10)
        chunk_producer_executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix='chunk-producer'
        )
        abort = threading.Event()

        if rate_limit is not None:
            rate_limiter = utils.RateLimitedIO(rate_limit)
            upload_chunk_size = max(rate_limit // (self._concurrent * 16), 1)
        else:
            rate_limiter = None
            upload_chunk_size = DEFAULT_STREAM_CHUNK_SIZE

        state = _SnapshotState()
        chunks_table = {}
        snapshot_files = {}

        def _chunk_done(chunk: _SnapshotChunk):
            finished_files_count = 0
            bisect_point = bisect.bisect_left(state.files, (chunk.stream_end + 1,))

            for index in range(bisect_point - 1, -1, -1):
                _, file = state.files[index]
                if file.stream_end < chunk.stream_start:
                    break

                try:
                    file_data = snapshot_files[file.path]
                except KeyError:
                    file_data = snapshot_files[file.path] = {
                        'path': file.path,
                        'chunks': [],
                        'digest': None,
                        'metadata': None,
                    }

                part_start = max(file.stream_start - chunk.stream_start, 0)
                part_end = min(file.stream_end, chunk.stream_end) - chunk.stream_start
                file_data['chunks'].append(
                    {
                        'range': [part_start, part_end],
                        'index': chunk.table_index,
                        'counter': chunk.counter,
                    }
                )

                if chunk.stream_end >= file.stream_end and file.digest is not None:
                    # File completed
                    file_data['digest'] = file.digest
                    file_data['metadata'] = file.metadata
                    logger.info('File %r fully processed', file.path)
                    finished_files_count += 1

            finished_tracker.update(finished_files_count)
            bytes_tracker.update(chunk.stream_end - chunk.stream_start)

        def _stream_files(chunk_size=16_777_216):
            for path in files:
                if (prev_file := state.current_file) is not None:
                    # Produce padding for the previous file
                    # TODO: let the chunker generate the padding?
                    if alignment := self.props.chunker.alignment:
                        padding_length = (
                            -(prev_file.stream_end - prev_file.stream_start) % alignment
                        )
                        if padding_length:
                            state.bytes_with_padding += padding_length
                            yield bytes(padding_length)

                    logger.info('Finished streaming file %r', prev_file.path)

                logger.info('Started streaming file %r', str(path))

                file = _SnapshotFile(
                    path=str(path),
                    stream_start=state.bytes_with_padding,
                    stream_end=state.bytes_with_padding,
                )
                state.current_file = file
                state.files.append((file.stream_start, file))
                hasher = self.props.incremental_hasher()

                with path.open('rb') as source_file:
                    while chunk := source_file.read(chunk_size):
                        state.bytes_with_padding += len(chunk)
                        file.stream_end += len(chunk)
                        hasher.feed(chunk)
                        yield chunk

                    file.digest = hasher.digest()
                    file.metadata = self.read_metadata(source_file.fileno())

            if state.current_file is not None:
                logger.info(
                    'Finished streaming file %r, stopping', state.current_file.path
                )

        def _chunk_producer():
            # Will run in a different thread, because most of these actions release GIL
            for output_chunk in self.props.chunkify(_stream_files()):
                state.chunk_counter += 1
                stream_start = state.bytes_chunked
                state.bytes_chunked += len(output_chunk)
                digest = self.props.hash_digest(output_chunk)

                try:
                    index = chunks_table[digest]
                except KeyError:
                    index = chunks_table[digest] = len(chunks_table)
                    logger.info('Added digest %s to the table (I=%d)', digest, index)

                if self.props.encrypted:
                    encrypted_contents = self.props.encrypt(
                        output_chunk, self.props.derive_shared_subkey(digest)
                    )
                else:
                    encrypted_contents = output_chunk

                chunk = _SnapshotChunk(
                    contents=encrypted_contents,
                    table_index=index,
                    location=self._chunk_digest_to_location(digest),
                    counter=state.chunk_counter,
                    stream_start=stream_start,
                    stream_end=stream_start + len(output_chunk),
                )

                while True:
                    if abort.is_set():
                        logging.info('Stopping chunk producer')
                        return

                    try:
                        chunk_queue.put(chunk, timeout=_queue_timeout)
                    except queue.Full:
                        pass
                    else:
                        break

        async def _worker():
            while not chunk_queue.empty() or not chunk_producer.done():
                try:
                    chunk = chunk_queue.get_nowait()
                except queue.Empty:
                    await asyncio.sleep(_queue_timeout)
                    continue

                exists = await self._exists(chunk.location)
                logger.info(
                    'Processing chunk #%d, exists=%s, I=%d, L=%s',
                    chunk.counter,
                    exists,
                    chunk.table_index,
                    chunk.location,
                )
                if exists:
                    _chunk_done(chunk)
                    state.bytes_reused += chunk.stream_end - chunk.stream_start
                else:
                    async with self._acquire_slot() as slot:
                        length = len(chunk.contents)
                        stream = io.BytesIO(chunk.contents)

                        if rate_limiter is not None:
                            limited_wrapper = rate_limiter.wrap(stream)
                        else:
                            limited_wrapper = stream

                        tqdm_wrapper = utils.TQDMIOReader(
                            limited_wrapper,
                            desc=f'Chunk #{chunk.counter:06}',
                            total=length,
                            position=slot,
                            disable=self._quiet,
                        )
                        with stream, limited_wrapper, tqdm_wrapper:
                            await self._maybe_run_in_executor(
                                self.backend.upload_stream,
                                chunk.location,
                                tqdm_wrapper,
                                length,
                                upload_chunk_size,
                            )

                    _chunk_done(chunk)

        chunk_producer = loop.run_in_executor(chunk_producer_executor, _chunk_producer)

        bytes_tracker = tqdm(
            desc='Data processed',
            unit='B',
            unit_scale=True,
            total=None,
            position=0,
            disable=self._quiet,
            leave=True,
        )
        finished_tracker = tqdm(
            desc='Files processed',
            unit='',
            total=len(files),
            position=1,
            disable=self._quiet,
            leave=True,
        )

        with finished_tracker, bytes_tracker:
            try:
                await asyncio.gather(*(_worker() for _ in range(self._concurrent)))
            except:
                abort.set()
                raise
            finally:
                await chunk_producer

        now = datetime.utcnow()
        snapshot_data = {
            'utc_timestamp': str(now),
            'files': list(snapshot_files.values()),
            # TODO: 'config', 'version', 'uid', 'gid', 'hostname', 'platform'?
        }
        if note is not None:
            snapshot_data['note'] = note

        snapshot_body = {'chunks': list(chunks_table), 'data': snapshot_data}
        logger.debug(
            'Generated snapshot: %s',
            json.dumps(
                snapshot_body,
                indent=4,
                default=self.default_serialization_hook,
            ),
        )
        serialized_snapshot = self._encrypt_snapshot_body(snapshot_body)
        digest = self.props.hash_digest(serialized_snapshot)
        name, tag = self._snapshot_digest_to_location_parts(digest)
        location = self.get_snapshot_location(name=name, tag=tag)

        self.display_status(f'Uploading snapshot {name}')
        await self._upload_data(location, serialized_snapshot)

        if state.bytes_reused:
            reused_human = utils.bytes_to_human(state.bytes_reused)
            self.display_status(f'Used {reused_human} of existing data')

        return utils.DefaultNamespace(
            name=name,
            tag=tag,
            location=location,
            chunks=snapshot_body['chunks'],
            data=snapshot_body['data'],
        )

    def _write_file_part(self, path, data, offset):
        logger.info(
            'Writing %d bytes to %s starting from %d',
            len(data),
            path,
            offset,
        )
        try:
            file = path.open('r+b')
        except FileNotFoundError:
            path.parent.mkdir(parents=True, exist_ok=True)
            file = path.open('wb')

        with file:
            file_end = file.seek(0, io.SEEK_END)
            file.truncate(max(file_end, offset + len(data)))
            file.seek(offset)
            file.write(data)

    async def restore(
        self, *, snapshot_regex=None, file_regex=None, path=None, rate_limit=None
    ):
        if path is None:
            path = Path()

        path = path.resolve()
        logger.info("Will restore files to %s", path)

        loop = asyncio.get_running_loop()
        loader = ThreadPoolExecutor(
            max_workers=self._concurrent * 2, thread_name_prefix='chunk-loader'
        )
        writer = ThreadPoolExecutor(
            max_workers=self._concurrent * 2, thread_name_prefix='file-writer'
        )

        if rate_limit is not None:
            rate_limiter = utils.RateLimitedIO(rate_limit)
            download_chunk_size = max(rate_limit // (self._concurrent * 16), 1)
        else:
            rate_limiter = None
            download_chunk_size = DEFAULT_STREAM_CHUNK_SIZE

        glock = threading.Lock()
        flocks = {}
        flocks_refcounts = {}

        def _write_chunk_ref(ref, contents):
            file_path, chunk_size, stream_start, start = ref
            restore_to, _ = files_metadata[file_path]

            with glock:
                try:
                    flock = flocks[restore_to]
                except KeyError:
                    flock = flocks[restore_to] = threading.Lock()
                    flocks_refcounts[restore_to] = 1
                else:
                    flocks_refcounts[restore_to] += 1

            with flock:
                self._write_file_part(
                    restore_to, contents[start : start + chunk_size], stream_start
                )

            with glock:
                bytes_tracker.update(chunk_size)
                flocks_refcounts[restore_to] -= 1
                if not flocks_refcounts[restore_to]:
                    del flocks_refcounts[restore_to], flocks[restore_to]

        def _download_chunk(digest, refs):
            location = self._chunk_digest_to_location(digest)
            # TODO: async backend methods will naturally do the writing from the
            # same (main) thread. This is suboptimal, even if we're more likely
            # to be restricted by the bandwidth. Should we use async files/offload
            # file IO to a dedicated executor?
            stream = io.BytesIO()

            if rate_limiter is not None:
                limited_wrapper = rate_limiter.wrap(stream)
            else:
                limited_wrapper = stream

            with self._acquire_slot_threadsafe(loop=loop) as slot:
                logger.info('Downloading chunk %r', location)
                tqdm_wrapper = utils.TQDMIOWriter(
                    limited_wrapper,
                    desc=location[:25],  # TODO: something even smarter?
                    total=None,
                    position=slot,
                    disable=self._quiet,
                )
                with stream, limited_wrapper, tqdm_wrapper:
                    self._maybe_run_coroutine_threadsafe(
                        self.backend.download_stream,
                        location,
                        tqdm_wrapper,
                        download_chunk_size,
                        loop=loop,
                    )
                    contents = stream.getvalue()

            logger.info('Decrypting %s', location)
            if self.props.encrypted:
                decrypted_contents = self.props.decrypt(
                    contents,
                    self.props.derive_shared_subkey(digest),
                )
            else:
                decrypted_contents = contents

            logger.info('Verifying %s', location)
            if self.props.hash_digest(decrypted_contents) != digest:
                raise exceptions.ReplicatError(f'Chunk at {location!r} is corrupted')

            logger.info('Chunk %s referenced %d time(s)', location, len(refs))
            decrypted_view = memoryview(decrypted_contents)
            writer_futures = []
            referenced_paths = set()

            for ref in refs:
                writer_futures.append(
                    writer.submit(_write_chunk_ref, ref, decrypted_view)
                )
                referenced_paths.add(ref[0])

            for future in concurrent.futures.as_completed(writer_futures):
                future.result()

            for file_path in referenced_paths:
                with glock:
                    digests = files_digests[file_path]
                    digests.remove(digest)

                if not digests:
                    logger.info('Finished writing file %s', file_path)
                    with glock:
                        restore_path, metadata = files_metadata.pop(file_path)
                    self.restore_metadata(restore_path, metadata)
                    finished_tracker.update()

        self.display_status('Loading snapshots')
        snapshots_gen = self._load_snapshots(snapshot_regex=snapshot_regex)
        snapshots = [x async for _, x in snapshots_gen if x['data'] is not None]
        snapshots.sort(key=lambda x: x['data']['utc_timestamp'], reverse=True)

        file_re = self._compile_or_none(file_regex)
        chunks_references = defaultdict(list)
        files_digests = {}
        files_metadata = {}
        total_bytes = 0

        for snapshot_body in snapshots:
            snapshot_chunks = snapshot_body['chunks']
            snapshot_data = snapshot_body['data']

            for file_data in snapshot_data['files']:
                if (file_path := file_data['path']) in files_digests:
                    continue

                if file_re is not None and file_re.search(file_path) is None:
                    logger.info('Skipping %s (does not match the filter)', file_path)
                    continue

                restore_to = Path(path, *Path(file_path).parts[1:]).resolve()
                files_metadata[file_path] = (restore_to, file_data['metadata'])
                digests = files_digests[file_path] = set()

                ordered_chunks = sorted(file_data['chunks'], key=lambda x: x['counter'])
                chunk_position = 0

                for chunk_data in ordered_chunks:
                    digest = snapshot_chunks[chunk_data['index']]
                    digests.add(digest)

                    start, end = chunk_data['range']
                    chunk_size = end - start
                    chunks_references[digest].append(
                        (
                            file_path,
                            chunk_size,
                            chunk_position,
                            start,
                        )
                    )
                    chunk_position += chunk_size

                total_bytes += chunk_position

        bytes_tracker = tqdm(
            desc='Data processed',
            unit='B',
            unit_scale=True,
            total=total_bytes,
            position=0,
            disable=self._quiet,
            leave=True,
        )
        finished_tracker = tqdm(
            desc='Files restored',
            unit='',
            total=len(files_metadata),
            position=1,
            disable=self._quiet,
            leave=True,
        )

        with finished_tracker, bytes_tracker:
            await asyncio.gather(
                *(
                    loop.run_in_executor(loader, _download_chunk, *x)
                    for x in chunks_references.items()
                )
            )

        return utils.DefaultNamespace(files=list(files_digests))

    def _format_snapshot_info_brief(self, snapshot_data):
        parts = []
        if (note := self._extract_snapshot_note(snapshot_data)) is not None:
            parts.append(note)

        dt = self._extract_snapshot_utc_timestamp(snapshot_data)
        file_count = self._extract_snapshot_file_count(snapshot_data)
        size = self._extract_snapshot_size(snapshot_data)
        parts.append('from ' + dt.isoformat(sep=' ', timespec='seconds'))
        parts.append(
            'with {} {}'.format(file_count, 'file' if file_count == 1 else 'files')
        )
        parts.append(utils.bytes_to_human(size))
        return ', '.join(parts)

    async def delete_snapshots(self, snapshots, /, *, confirm=True):
        # TODO: locking
        self.display_status('Loading snapshots')
        chunks_to_delete = set()
        chunks_to_keep = set()
        snapshots_locations = set()
        remaining_names = set(snapshots)
        danger_message_parts = ['The following snapshots will be deleted:']

        async for path, body in self._load_snapshots():
            name = self.parse_snapshot_location(path).name
            if name in remaining_names:
                if (snapshot_data := body['data']) is None:
                    raise exceptions.ReplicatError(
                        f'Cannot delete snapshot {name} (different key)'
                    )

                chunks_to_delete.update(body['chunks'])
                snapshots_locations.add(path)
                remaining_names.discard(name)
                danger_message_parts.append(
                    '    {} ({})'.format(
                        name, self._format_snapshot_info_brief(snapshot_data)
                    )
                )
            else:
                chunks_to_keep.update(body['chunks'])

        if remaining_names:
            raise exceptions.ReplicatError(
                f'Snapshots {", ".join(remaining_names)} are not available'
            )

        if confirm:
            self.display_danger('\n'.join(danger_message_parts))
            if input('Proceed? [y/n] ').lower() != 'y':
                logger.info('Aborting')
                return

        chunks_to_delete.difference_update(chunks_to_keep)

        async def _delete_snapshot(location):
            await self._delete(location)
            if self._cache_directory is not None:
                self._delete_cached(location)
            finished_snapshots_tracker.update()

        async def _delete_chunk(digest):
            location = self._chunk_digest_to_location(digest)
            await self._delete(location)
            finished_chunks_tracker.update()

        finished_snapshots_tracker = tqdm(
            desc='Snapshots deleted',
            unit='',
            total=len(snapshots_locations),
            position=0,
            disable=self._quiet,
            leave=True,
        )

        with finished_snapshots_tracker:
            await asyncio.gather(*map(_delete_snapshot, snapshots_locations))

        finished_chunks_tracker = tqdm(
            desc='Unreferenced chunks deleted',
            unit='',
            total=len(chunks_to_delete),
            position=0,
            disable=self._quiet,
            leave=True,
        )

        with finished_chunks_tracker:
            await asyncio.gather(*map(_delete_chunk, chunks_to_delete))

    async def clean(self):
        # TODO: locking
        self.display_status('Loading snapshots')
        referenced_digests = {
            y async for _, x in self._load_snapshots() for y in x['chunks']
        }
        referenced_locations = set(
            map(self._chunk_digest_to_location, referenced_digests)
        )
        to_delete = set()

        self.display_status('Fetching chunk list')
        async for location in self._aiter(self.backend.list_files, self.CHUNK_PREFIX):
            if location in referenced_locations:
                logger.info('Chunk %s is referenced, skipping', location)
                continue

            if self.props.encrypted:
                logger.info('Validating tag for %s', location)
                name, tag = self.parse_chunk_location(location)
                if self.props.mac(bytes.fromhex(name)) != bytes.fromhex(tag):
                    logger.info('Tag for %s did not match, skipping', location)
                    continue

            to_delete.add(location)

        if not to_delete:
            return

        async def _delete_chunk(location):
            await self._delete(location)
            finished_tracker.update()

        finished_tracker = tqdm(
            desc='Unreferenced chunks deleted',
            unit='',
            total=len(to_delete),
            position=0,
            disable=self._quiet,
            leave=True,
        )

        with finished_tracker:
            await asyncio.gather(*map(_delete_chunk, to_delete))

        self.display_status('Running post-deletion cleanup')
        await self._clean()

    @utils.disable_gc
    def _benchmark_chunker(self, adapter, number=10, size=512_000_000):
        prep_time = 0

        def _stream(seed=0):
            nonlocal prep_time
            method = Random(seed).randbytes
            for _ in range(number):
                start = time.perf_counter_ns()
                buffer = bytearray()
                while len(buffer) < size:
                    buffer += method(16_777_216)
                del buffer[size:]
                prep_time += time.perf_counter_ns() - start
                yield buffer

        stream = _stream()
        start = time.perf_counter_ns()
        processed_bytes = sum(map(len, adapter(stream)))
        elapsed = Decimal(time.perf_counter_ns() - start - prep_time).scaleb(-9)
        rate = processed_bytes / elapsed
        self.display_status(
            f'Processed {utils.bytes_to_human(processed_bytes, 3)} '
            f'in {elapsed:.3f} seconds ({utils.bytes_to_human(rate, 3)}/s)'
        )

    async def benchmark(self, name, settings=None):
        logger.info('Using provided settings: %r', settings)
        if settings is None:
            settings = {}

        adapter_type, adapter_args = adapters.from_config(name=name, **settings)
        adapter = adapter_type(**adapter_args)
        argument_string = ', '.join(
            f'{name}={value!r}' for name, value in adapter_args.items()
        )
        self.display_status(f'Benchmarking {name}({argument_string})')
        benchmarker = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix='benchmarker'
        )

        if isinstance(adapter, adapters.ChunkerAdapter):
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(benchmarker, self._benchmark_chunker, adapter)
        else:
            raise RuntimeError('Sorry, not yet')

    async def upload_objects(self, paths, *, rate_limit=None, skip_existing=False):
        self.display_status('Collecting files')
        files = self._flatten_resolve_paths(paths)
        logger.info('Found %d files to upload', len(files))
        if not files:
            return

        working_directory = Path.cwd()

        if rate_limit is not None:
            rate_limiter = utils.RateLimitedIO(rate_limit)
            upload_chunk_size = max(rate_limit // (self._concurrent * 16), 1)
        else:
            rate_limiter = None
            upload_chunk_size = DEFAULT_STREAM_CHUNK_SIZE

        async def _upload_file(path):
            name = path.relative_to(
                os.path.commonpath([path, working_directory])
            ).as_posix()

            if skip_existing and await self._exists(name):
                logger.info('Skipping file %r (exists)', name)
            else:
                async with self._acquire_slot() as slot:
                    logger.info('Uploading file %r', name)
                    # TODO: async backend methods will naturally do the reading from the
                    # same (main) thread. This is suboptimal, even if we're more likely
                    # to be restricted by the bandwidth. Should we use async files/offload
                    # file IO to a dedicated executor?
                    stream = path.open('rb')
                    length = os.fstat(stream.fileno()).st_size

                    if rate_limiter is not None:
                        limited_wrapper = rate_limiter.wrap(stream)
                    else:
                        limited_wrapper = stream

                    callback_wrapper = CallbackIOWrapper(
                        bytes_tracker.update, limited_wrapper, 'read'
                    )
                    tqdm_wrapper = utils.TQDMIOReader(
                        callback_wrapper,
                        desc=name,
                        total=length,
                        position=slot,
                        disable=self._quiet,
                    )

                    with stream, limited_wrapper, tqdm_wrapper:
                        await self._maybe_run_in_executor(
                            self.backend.upload_stream,
                            name,
                            tqdm_wrapper,
                            length,
                            upload_chunk_size,
                        )

            finished_tracker.update()

        bytes_tracker = tqdm(
            desc='Data uploaded',
            unit='B',
            unit_scale=True,
            total=None,
            position=0,
            disable=self._quiet,
            leave=True,
        )
        finished_tracker = tqdm(
            desc='Files processed',
            unit='',
            total=len(files),
            position=1,
            disable=self._quiet,
            leave=True,
        )

        with finished_tracker, bytes_tracker:
            await asyncio.gather(*map(_upload_file, files))

        return utils.DefaultNamespace(files=files)

    async def download_objects(
        self,
        *,
        path=None,
        object_prefix='',
        object_regex=None,
        rate_limit=None,
        skip_existing=False,
    ):
        self.display_status('Loading object list')
        object_re = self._compile_or_none(object_regex)
        objects = []

        async for object_path in self._aiter(self.backend.list_files, object_prefix):
            if object_re is not None and object_re.search(object_path) is None:
                logger.info('Skipping %s (does not match the filter)', object_path)
                continue

            objects.append(object_path)

        logger.info('Found %d objects to download', len(objects))
        if not objects:
            return

        base_directory = path if path is not None else Path.cwd()
        write_mode = 'xb' if skip_existing else 'wb'

        if rate_limit is not None:
            rate_limiter = utils.RateLimitedIO(rate_limit)
            download_chunk_size = max(rate_limit // (self._concurrent * 16), 1)
        else:
            rate_limiter = None
            download_chunk_size = DEFAULT_STREAM_CHUNK_SIZE

        async def _download_object(object_path):
            output_path = base_directory / object_path

            async with self._acquire_slot() as slot:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                try:
                    stream = output_path.open(write_mode)
                except FileExistsError:
                    logger.info('Skipping object %r (file exists)', output_path)
                else:
                    logger.info('Downloading object %r', object_path)
                    # TODO: async backend methods will naturally do the writing from the
                    # same (main) thread. This is suboptimal, even if we're more likely
                    # to be restricted by the bandwidth. Should we use async files/offload
                    # file IO to a dedicated executor?
                    if rate_limiter is not None:
                        limited_wrapper = rate_limiter.wrap(stream)
                    else:
                        limited_wrapper = stream

                    callback_wrapper = CallbackIOWrapper(
                        bytes_tracker.update, limited_wrapper, 'write'
                    )
                    tqdm_wrapper = utils.TQDMIOWriter(
                        callback_wrapper,
                        desc=object_path[:25],  # TODO: something even smarter?
                        total=None,
                        position=slot,
                        disable=self._quiet,
                    )

                    with stream, limited_wrapper, tqdm_wrapper:
                        await self._maybe_run_in_executor(
                            self.backend.download_stream,
                            object_path,
                            tqdm_wrapper,
                            download_chunk_size,
                        )

            finished_tracker.update()

        bytes_tracker = tqdm(
            desc='Data downloaded',
            unit='B',
            unit_scale=True,
            total=None,
            position=0,
            disable=self._quiet,
            leave=True,
        )
        finished_tracker = tqdm(
            desc='Objects processed',
            unit='',
            total=len(objects),
            position=1,
            disable=self._quiet,
            leave=True,
        )

        with finished_tracker, bytes_tracker:
            await asyncio.gather(*map(_download_object, objects))

        return utils.DefaultNamespace(objects=objects)

    async def list_objects(
        self,
        *,
        object_prefix='',
        object_regex=None,
    ):
        object_re = self._compile_or_none(object_regex)
        paths = []

        self.display_status('Loading object list')
        async for object_path in self._aiter(self.backend.list_files, object_prefix):
            if object_re is not None and object_re.search(object_path) is None:
                logger.info('Skipping %s (does not match the filter)', object_path)
                continue

            paths.append(object_path)
            print(object_path)

        return utils.DefaultNamespace(paths=paths)

    async def delete_objects(self, object_paths, /, *, confirm=True):
        if confirm:
            message_parts = ['The following objects will be deleted:']
            message_parts.extend(f'    {x}' for x in object_paths)
            self.display_danger('\n'.join(message_parts))
            if input('Proceed? [y/n] ').lower() != 'y':
                logger.info('Aborting')
                return

        async def _delete_object(location):
            await self._delete(location)
            if self._cache_directory is not None:
                self._delete_cached(location)
            deleted_objects_tracker.update()

        deleted_objects_tracker = tqdm(
            desc='Objects deleted',
            unit='',
            total=len(object_paths),
            position=0,
            disable=self._quiet,
            leave=True,
        )

        with deleted_objects_tracker:
            await asyncio.gather(*map(_delete_object, object_paths))

    async def close(self):
        try:
            del self.props
        except AttributeError:
            pass

        await self._close()
