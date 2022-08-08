import asyncio
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
from collections import defaultdict, namedtuple
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime
from decimal import Decimal
from functools import cached_property
from pathlib import Path
from typing import Any, Dict, Optional

from sty import ef
from tqdm import tqdm

from . import exceptions, utils
from .utils.adapters import (
    ChunkerAdapter,
    CipherAdapter,
    HashAdapter,
    KDFAdapter,
    MACAdapter,
)
from .utils.compat import Random

logger = logging.getLogger(__name__)
LocationParts = namedtuple('LocationParts', ['name', 'tag'])


@dataclasses.dataclass(frozen=True)
class _SnapshotChunk:
    contents: bytes
    index: int
    location: str
    stream_start: int
    stream_end: int
    counter: int


@dataclasses.dataclass(repr=False, frozen=True)
class RepositoryProps:
    chunker: ChunkerAdapter
    hasher: HashAdapter
    cipher: Optional[CipherAdapter] = None
    userkey: Optional[bytes] = None
    authenticator: Optional[MACAdapter] = None
    shared_kdf: Optional[KDFAdapter] = None
    private: Optional[Dict[str, Any]] = None

    @cached_property
    def encrypted(self):
        return self.cipher is not None

    def hash_digest(self, data):
        return self.hasher.digest(data)

    def encrypt(self, data, key):
        assert self.encrypted
        return self.cipher.encrypt(data, key)

    def decrypt(self, data, key):
        assert self.encrypted
        return self.cipher.decrypt(data, key)

    def mac(self, data):
        assert self.encrypted
        return self.authenticator.mac(data, params=self.private['mac_params'])

    def derive_shared_subkey(self, ctx):
        assert self.encrypted
        return self.shared_kdf.derive(
            self.private['shared_key'],
            context=ctx,
            params=self.private['shared_kdf_params'],
        )

    def chunkify(self, it):
        params = self.private['chunker_params'] if self.encrypted else None
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
    DEFAULT_CACHE_DIRECTORY = utils.fs.DEFAULT_CACHE_DIRECTORY

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

        self._slots = asyncio.Queue(maxsize=concurrent)
        # We need actual integers for TQDM slot management in CLI, but this queue
        # can also act as a semaphore in the general case. Note that numbering starts
        # from 2, leaving two topmost slots to non-slotable trackers
        for slot in range(2, concurrent + 2):
            self._slots.put_nowait(slot)

        self.backend = backend

    def display_status(self, message):
        print(ef.bold + message + ef.rs, file=sys.stderr)

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
    def _backend_executor(self):
        """Executor for non-async methods of the backend instance"""
        return ThreadPoolExecutor(
            max_workers=self._concurrent, thread_name_prefix='backend-method-runner'
        )

    def _abwrap(self, func, *args, **kwargs):
        # Async backend wrapper, should only be used for backend methods
        if inspect.iscoroutinefunction(func) or inspect.isasyncgenfunction(func):
            return func(*args, **kwargs)
        else:
            loop = asyncio.get_running_loop()
            return loop.run_in_executor(self._backend_executor, func, *args, **kwargs)

    async def _abiter(self, func, *args, **kwargs):
        # Async backend iterator, should only be used for backend methods
        unknown = self._abwrap(func, *args, **kwargs)
        if inspect.isawaitable(unknown):
            result = await unknown
        else:
            result = unknown

        if not isinstance(result, collections.abc.AsyncIterable):
            result = utils.async_gen_wrapper(result)

        async for value in result:
            yield value

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

    # Convenience wrappers for backend methods that do not need to know
    # the actual slot they are occupying (so most of them)
    async def _exists(self, location):
        async with self._acquire_slot():
            logger.info('Checking existence of %s', location)
            return await self._abwrap(self.backend.exists, location)

    async def _download(self, location):
        async with self._acquire_slot():
            logger.info('Downloading %s', location)
            return await self._abwrap(self.backend.download, location)

    async def _upload_data(self, location, data):
        async with self._acquire_slot():
            logger.info('Uploading binary data to %s', location)
            await self._abwrap(self.backend.upload, location, data)

    async def _delete(self, location):
        async with self._acquire_slot():
            logger.info('Deleting %s', location)
            await self._abwrap(self.backend.delete, location)

    async def _clean(self):
        async with self._acquire_slot():
            logger.info('Running backend clean-up')
            await self._abwrap(self.backend.clean)

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
            digest_mac = digest
            digest_mac_mac = digest

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

    def read_metadata(self, path, /):
        # TODO: Cache stat result?
        stat_result = os.stat(path)
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
        hasher_type, hasher_args = utils.adapter_from_config(**hashing_settings)
        config['hashing'] = dict(hasher_args, name=hasher_type.__name__)

        # Deduplication params
        chunking_settings = settings.get('chunking', {})
        chunking_settings.setdefault('name', self.DEFAULT_CHUNKER_NAME)
        chunker_type, chunker_args = utils.adapter_from_config(**chunking_settings)
        config['chunking'] = dict(chunker_args, name=chunker_type.__name__)

        if (encryption_settings := settings.get('encryption', {})) is not None:
            cipher_settings = encryption_settings.get('cipher', {})
            cipher_settings.setdefault('name', self.DEFAULT_CIPHER_NAME)
            cipher_type, cipher_args = utils.adapter_from_config(**cipher_settings)
            config['encryption'] = {
                'cipher': dict(cipher_args, name=cipher_type.__name__)
            }

        return config

    def _instantiate_config(self, config):
        chunker_type, chunker_args = utils.adapter_from_config(**config['chunking'])
        hasher_type, hasher_args = utils.adapter_from_config(**config['hashing'])

        if (encryption_config := config.get('encryption')) is not None:
            cipher_type, cipher_args = utils.adapter_from_config(
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

    def _make_key(self, *, cipher, chunker, settings=None, private=None):
        if settings is None:
            settings = {}

        encryption_settings = settings.get('encryption', {})
        # KDF for user personal data
        user_kdf_settings = encryption_settings.get('kdf', {})
        user_kdf_settings.setdefault('name', self.DEFAULT_USER_KDF_NAME)
        user_kdf_type, user_kdf_args = utils.adapter_from_config(
            **user_kdf_settings, length=cipher.key_bytes
        )
        user_kdf = user_kdf_type(**user_kdf_args)

        if private is None:
            # KDF for shared data
            shared_kdf_settings = encryption_settings.get('shared_kdf', {})
            shared_kdf_settings.setdefault('name', self.DEFAULT_SHARED_KDF_NAME)
            shared_kdf_type, shared_args = utils.adapter_from_config(
                **shared_kdf_settings, length=cipher.key_bytes
            )
            shared_kdf = shared_kdf_type(**shared_args)

            # Message authentication
            mac_settings = encryption_settings.get('mac', {})
            mac_settings.setdefault('name', self.DEFAULT_MAC_NAME)
            mac_type, mac_args = utils.adapter_from_config(**mac_settings)
            mac = mac_type(**mac_args)

            private = {
                'shared_key': cipher.generate_key(),
                'shared_kdf': dict(shared_args, name=shared_kdf_type.__name__),
                'shared_kdf_params': shared_kdf.generate_derivation_params(),
                'mac': dict(mac_args, name=mac_type.__name__),
                'mac_params': mac.generate_mac_params(),
                'chunker_params': chunker.generate_chunking_params(),
            }

        return {
            'kdf': dict(user_kdf_args, name=user_kdf_type.__name__),
            'kdf_params': user_kdf.generate_derivation_params(),
            'private': private,
        }

    def _instantiate_key(self, key, *, password, cipher):
        # User key derivation
        kdf_type, kdf_args = utils.adapter_from_config(**key['kdf'])
        userkey = kdf_type(**kdf_args).derive(password, params=key['kdf_params'])

        if isinstance(key['private'], bytes):
            # The 'private' portion of the key is still encrypted
            private = self.deserialize(cipher.decrypt(key['private'], userkey))
        else:
            private = key['private']

        # Message authentication
        authenticator_type, authenticator_args = utils.adapter_from_config(
            **private['mac']
        )
        # KDF for shared data
        shared_kdf_type, shared_kdf_args = utils.adapter_from_config(
            **private['shared_kdf']
        )

        return {
            'userkey': userkey,
            'authenticator': authenticator_type(**authenticator_args),
            'shared_kdf': shared_kdf_type(**shared_kdf_args),
            'private': private,
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
            if password is None:
                raise exceptions.ReplicatError(
                    'A password is needed to initialize encrypted repository'
                )

            key = self._make_key(
                cipher=props.cipher, chunker=props.chunker, settings=settings
            )
            props = dataclasses.replace(
                props,
                **self._instantiate_key(key, password=password, cipher=props.cipher),
            )
            # Encrypt the private portion
            logger.debug('Private key portion (unencrypted): %r', key['private'])
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

    async def _load_config(self):
        data = await self._download('config')
        return RepositoryProps(**self._instantiate_config(self.deserialize(data)))

    async def unlock(self, *, password=None, key=None):
        self.display_status('Loading config')
        props = await self._load_config()

        if props.encrypted:
            self.display_status('Unlocking repository')
            if password is None or key is None:
                raise exceptions.ReplicatError(
                    'Both password and key are needed to unlock this repository'
                )

            # TODO: Load keys from the backend as a fallback?
            if isinstance(key, collections.abc.ByteString):
                key = self.deserialize(key)

            props = dataclasses.replace(
                props,
                **self._instantiate_key(key, password=password, cipher=props.cipher),
            )

        self.props = props

    async def _add_key(self, *, password, settings, props, private, key_output_path):
        self.display_status('Generating new key')
        key = self._make_key(
            cipher=props.cipher,
            chunker=props.chunker,
            settings=settings,
            private=private,
        )
        key_props = self._instantiate_key(key, password=password, cipher=props.cipher)

        # Encrypt the private portion
        logger.debug('Private portion of the new key (unencrypted): %r', key['private'])
        key['private'] = props.encrypt(
            self.serialize(key['private']),
            key_props['userkey'],
        )
        # TODO: store it in the repository?
        if key_output_path is not None:
            key_output_path = Path(key_output_path).resolve()
            self.display_status(f'Writing key to {key_output_path}')
            key_output_path.write_bytes(self.serialize(key))
        else:
            print(json.dumps(key, indent=4, default=self.default_serialization_hook))

        return key

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
        if password is None:
            raise exceptions.ReplicatError(
                'The password is required to generate a new key'
            )

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
                props = await self._load_config()

        if not props.encrypted:
            raise exceptions.ReplicatError('Repository is not encrypted')

        key = await self._add_key(
            password=password,
            settings=settings,
            props=props,
            private=private,
            key_output_path=key_output_path,
        )
        return utils.DefaultNamespace(new_key=key)

    def _download_snapshot(self, path, expected_digest, *, loop):
        contents = None
        if self._cache_directory is not None:
            try:
                contents = self._get_cached(path)
            except FileNotFoundError:
                pass

        if contents is None:
            with self._acquire_slot_threadsafe(loop=loop):
                logger.info('Downloading %s', path)
                if inspect.iscoroutinefunction(self.backend.download):
                    contents = asyncio.run_coroutine_threadsafe(
                        self.backend.download(path), loop
                    ).result()
                else:
                    contents = self.backend.download(path)

            logger.info('Verifying %s', path)
            if self.props.hash_digest(contents) != expected_digest:
                raise exceptions.ReplicatError(f'Snapshot at {path!r} is corrupted')

            if self._cache_directory is not None:
                logger.info('Caching %s', path)
                self._store_cached(path, contents)

        body = self.deserialize(contents)

        if self.props.encrypted:
            logger.info('Decrypting %s', path)
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
                logger.info(
                    "Decryption of %s failed, but it's not corrupted (different key?)",
                    path,
                )
                body['data'] = None
            else:
                body['data'] = self.deserialize(data)

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

        def _download_snapshot(path):
            name, tag = self.parse_snapshot_location(path)
            if snapshot_regex is not None and re.search(snapshot_regex, name) is None:
                logger.info('Skipping %s (does not match the filter)', path)
                return

            digest = bytes.fromhex(name)
            if self.props.encrypted and self.props.mac(digest) != bytes.fromhex(tag):
                logger.info('Skipping %s (invalid tag)', path)
                return

            return self._download_snapshot(path, digest, loop=loop)

        async for path in self._abiter(self.backend.list_files, self.SNAPSHOT_PREFIX):
            future = loop.run_in_executor(loader, _download_snapshot, path)
            future_to_path[future] = path

        async for task in utils.as_completed(future_to_path):
            if (body := await task) is None:
                continue
            yield future_to_path[task], body

    def _format_snapshot_name(self, *, path, chunks, data):
        return self.parse_snapshot_location(path).name

    def _format_snapshot_note(self, *, path, chunks, data):
        return data and data.get('note')

    def _format_snapshot_utc_timestamp(self, *, path, chunks, data):
        if data is None or (value := data.get('utc_timestamp')) is None:
            return None

        dt = datetime.fromisoformat(value)
        return dt.isoformat(sep=' ', timespec='seconds')

    def _format_snapshot_files_count(self, *, path, chunks, data):
        if data is None or (files := data.get('files')) is None:
            return None

        return len(files)

    def _format_snaphot_size(self, *, path, chunks, data):
        if data is None or (files := data.get('files')) is None:
            return None

        ranges_it = (chunk['range'] for file in files for chunk in file['chunks'])
        return utils.bytes_to_human(sum(r[1] - r[0] for r in ranges_it))

    async def list_snapshots(self, *, snapshot_regex=None):
        columns_getters = {
            'snapshot': self._format_snapshot_name,
            'note': self._format_snapshot_note,
            'timestamp (utc)': self._format_snapshot_utc_timestamp,
            'files': self._format_snapshot_files_count,
            'size': self._format_snaphot_size,
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

            for column, getter in columns_getters.items():
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

        formatted_headers = []
        for column in columns_widths:
            width = columns_widths[column] = max(len(column), columns_widths[column])
            formatted_headers.append(column.upper().center(width))

        print(*formatted_headers, sep='\t')
        for _, row in snapshots:
            print(
                *(value.ljust(columns_widths[col]) for col, value in row.items()),
                sep='\t',
            )

    def _format_file_snapshot_date(
        self, *, snapshot_path, snapshot_chunks, snapshot_data, file_data
    ):
        dt = datetime.fromisoformat(snapshot_data['utc_timestamp'])
        return dt.isoformat(sep=' ', timespec='seconds')

    def _format_file_path(
        self, *, snapshot_path, snapshot_chunks, snapshot_data, file_data
    ):
        return file_data['path']

    def _format_file_chunks_count(
        self, *, snapshot_path, snapshot_chunks, snapshot_data, file_data
    ):
        return len(file_data['chunks'])

    def _format_file_size(
        self, *, snapshot_path, snapshot_chunks, snapshot_data, file_data
    ):
        ranges_it = (cd['range'] for cd in file_data['chunks'])
        return utils.bytes_to_human(sum(r[1] - r[0] for r in ranges_it))

    async def list_files(self, *, snapshot_regex=None, files_regex=None):
        columns_getters = {
            'snapshot date': self._format_file_snapshot_date,
            'path': self._format_file_path,
            'chunks count': self._format_file_chunks_count,
            'size': self._format_file_size,
        }
        columns_widths = {}
        files = []

        self.display_status('Loading snapshots')
        async for snapshot_path, snapshot_body in self._load_snapshots(
            snapshot_regex=snapshot_regex
        ):
            snapshot_chunks = snapshot_body['chunks']
            snapshot_data = snapshot_body['data']
            if snapshot_data is None:
                continue

            for file_data in snapshot_data['files']:
                if files_regex is not None:
                    if re.search(files_regex, file_data['path']) is None:
                        continue

                row = {}
                for column, getter in columns_getters.items():
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

        formatted_headers = []
        for column in columns_widths:
            width = columns_widths[column] = max(len(column), columns_widths[column])
            formatted_headers.append(column.upper().center(width))

        print(*formatted_headers, sep='\t')
        for _, row in files:
            print(
                *(value.ljust(columns_widths[col]) for col, value in row.items()),
                sep='\t',
            )

    def _flatten_paths(self, paths):
        return list(utils.fs.flatten_paths(path.resolve(strict=True) for path in paths))

    async def snapshot(self, *, paths, note=None, rate_limit=None):
        self.display_status('Collecting files')
        files = self._flatten_paths(paths)
        logger.info('Found %d files', len(files))
        # Small files are more likely to change than big files, read them quickly
        # and bundle them together
        files.sort(key=lambda file: (file.stat().st_size, str(file)))

        state = utils.DefaultNamespace(
            bytes_with_padding=0,
            bytes_chunked=0,
            bytes_reused=0,
            chunk_counter=0,
            # Preallocate this dictionary to avoid concurrent insertions
            file_ranges=dict.fromkeys(files),
            files_finished=set(),
            current_file=None,
        )
        chunks_table = {}
        snapshot_files = {}
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
        loop = asyncio.get_running_loop()
        chunk_queue = queue.Queue(maxsize=self._concurrent * 10)
        abort = threading.Event()

        if rate_limit is not None:
            rate_limiter = utils.RateLimiter(rate_limit)
        else:
            rate_limiter = None

        def _chunk_done(chunk: _SnapshotChunk):
            for file, ranges in state.file_ranges.items():
                if ranges is None:
                    continue

                file_start, file_end = ranges
                if file_start > chunk.stream_end or file_end < chunk.stream_start:
                    continue

                part_start = max(file_start - chunk.stream_start, 0)
                part_end = min(file_end, chunk.stream_end) - chunk.stream_start

                if file not in snapshot_files:
                    snapshot_files[file] = {
                        'path': str(file.resolve()),
                        'chunks': [],
                        'metadata': self.read_metadata(file),
                    }

                snapshot_files[file]['chunks'].append(
                    {
                        'range': [part_start, part_end],
                        'index': chunk.index,
                        'counter': chunk.counter,
                    }
                )

                if chunk.stream_end >= file_end and file in state.files_finished:
                    # File completed
                    logger.info('File %r fully processed', str(file))
                    finished_tracker.update()

            bytes_tracker.update(chunk.stream_end - chunk.stream_start)

        def _stream_files():
            for file, source_chunk in utils.fs.stream_files(files):
                file_range = state.file_ranges[file]
                if file_range is not None:
                    start = file_range[0]
                else:
                    # First chunk from this file
                    if state.current_file is not None:
                        # Produce padding for the previous file
                        # TODO: let the chunker generate the padding?
                        if alignment := self.props.chunker.alignment:
                            cstart, cend = state.file_ranges[state.current_file]
                            if padding_length := -(cend - cstart) % alignment:
                                state.bytes_with_padding += padding_length
                                yield bytes(padding_length)

                        logger.info(
                            'Finished streaming file %r', str(state.current_file)
                        )
                        state.files_finished.add(state.current_file)

                    logger.info('Started streaming file %r', str(file))
                    state.current_file = file
                    start = state.bytes_with_padding

                state.bytes_with_padding += len(source_chunk)
                state.file_ranges[file] = (start, state.bytes_with_padding)
                yield source_chunk

            if state.current_file is not None:
                logger.info(
                    'Finished streaming file %r, stopping', str(state.current_file)
                )
                state.files_finished.add(state.current_file)

        def _chunk_producer(queue_timeout=0.025):
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
                    index=index,
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
                        chunk_queue.put(chunk, timeout=queue_timeout)
                    except queue.Full:
                        pass
                    else:
                        break

        async def _worker(queue_timeout=0.025):
            while not chunk_queue.empty() or not chunk_producer.done():
                try:
                    chunk = chunk_queue.get_nowait()
                except queue.Empty:
                    await asyncio.sleep(queue_timeout)
                    continue

                exists = await self._exists(chunk.location)
                logger.info(
                    'Processing chunk #%d, exists=%s, I=%d, L=%s',
                    chunk.counter,
                    exists,
                    chunk.index,
                    chunk.location,
                )
                if exists:
                    _chunk_done(chunk)
                    state.bytes_reused += chunk.stream_end - chunk.stream_start
                else:
                    async with self._acquire_slot() as slot:
                        length = len(chunk.contents)
                        stream = io.BytesIO(chunk.contents)
                        iowrapper = utils.tqdmio(
                            stream,
                            desc=f'Chunk #{chunk.counter:06}',
                            total=length,
                            position=slot,
                            disable=self._quiet,
                            rate_limiter=rate_limiter,
                        )
                        with stream, iowrapper:
                            await self._abwrap(
                                self.backend.upload_stream,
                                chunk.location,
                                iowrapper,
                                length,
                            )

                    _chunk_done(chunk)

        chunk_producer = loop.run_in_executor(
            ThreadPoolExecutor(max_workers=1, thread_name_prefix='chunk-producer'),
            _chunk_producer,
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

        if self.props.encrypted:
            encrypted_private_data = self.props.encrypt(
                self.serialize(snapshot_body['data']), self.props.userkey
            )
            encrypted_snapshot_body = {
                'chunks': self.props.encrypt(
                    self.serialize(snapshot_body['chunks']),
                    self.props.derive_shared_subkey(
                        self.props.hash_digest(encrypted_private_data)
                    ),
                ),
                'data': encrypted_private_data,
            }
        else:
            encrypted_snapshot_body = snapshot_body

        serialized_snapshot = self.serialize(encrypted_snapshot_body)
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

    async def restore(self, *, snapshot_regex=None, files_regex=None, path=None):
        if path is None:
            path = Path()

        path = path.resolve()
        logger.info("Will restore files to %s", path)

        loop = asyncio.get_running_loop()
        # We'll submit plain backend methods to this executor instead of the standard
        # one. We still need to use slots to limit concurrent calls to the backend
        loader = ThreadPoolExecutor(
            max_workers=self._concurrent, thread_name_prefix='chunk-loader'
        )
        writer = ThreadPoolExecutor(
            max_workers=self._concurrent * 3, thread_name_prefix='file-writer'
        )

        glock = threading.Lock()
        flocks = {}
        flocks_refcounts = {}

        chunks_references = defaultdict(list)
        files_digests = {}
        files_metadata = {}

        total_bytes = 0

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

            with self._acquire_slot_threadsafe(loop=loop):
                logger.info('Downloading %s', location)
                if inspect.iscoroutinefunction(self.backend.download):
                    contents = asyncio.run_coroutine_threadsafe(
                        self.backend.download(location), loop
                    ).result()
                else:
                    contents = self.backend.download(location)

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
            writer_futures = (
                writer.submit(_write_chunk_ref, ref, decrypted_view) for ref in refs
            )
            for future in concurrent.futures.as_completed(writer_futures):
                future.result()

            for ref in refs:
                file_path = ref[0]
                with glock:
                    digests = files_digests[file_path]
                    digests.remove(digest)

                if not digests:
                    logger.info('Finished writing file %s', file_path)
                    with glock:
                        restore_path, metadata = files_metadata.pop(file_path)
                    self.restore_metadata(restore_path, metadata)

        self.display_status('Loading snapshots')
        snapshots_gen = self._load_snapshots(snapshot_regex=snapshot_regex)
        snapshots = [x async for _, x in snapshots_gen if x['data'] is not None]
        snapshots.sort(key=lambda x: x['data']['utc_timestamp'], reverse=True)

        for snapshot_body in snapshots:
            snapshot_chunks = snapshot_body['chunks']
            snapshot_data = snapshot_body['data']

            for file_data in snapshot_data['files']:
                if (file_path := file_data['path']) in files_digests:
                    continue

                if files_regex is not None:
                    if re.search(files_regex, file_path) is None:
                        logger.info(
                            'Skipping %s (does not match the filter)', file_path
                        )
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
        with bytes_tracker:
            await asyncio.gather(
                *(
                    loop.run_in_executor(loader, _download_chunk, *x)
                    for x in chunks_references.items()
                )
            )

        return utils.DefaultNamespace(files=list(files_digests))

    async def delete_snapshots(self, snapshots):
        # TODO: locking
        self.display_status('Loading snapshots')
        to_delete = set()
        to_keep = set()
        snapshots_locations = set()
        remaining_names = set(snapshots)

        async for path, body in self._load_snapshots():
            name = self.parse_snapshot_location(path).name
            if name in remaining_names:
                if body['data'] is None:
                    raise exceptions.ReplicatError(
                        f'Cannot delete snapshot {name} (different key)'
                    )

                to_delete.update(body['chunks'])
                snapshots_locations.add(path)
                remaining_names.discard(name)
            else:
                to_keep.update(body['chunks'])

        if remaining_names:
            raise exceptions.ReplicatError(
                f'Snapshots {", ".join(remaining_names)} are not available'
            )

        to_delete.difference_update(to_keep)

        finished_snapshots_tracker = tqdm(
            desc='Snapshots deleted',
            unit='',
            total=len(snapshots_locations),
            position=0,
            disable=self._quiet,
            leave=True,
        )

        async def _delete_snapshot(location):
            await self._delete(location)
            if self._cache_directory is not None:
                self._delete_cached(location)
            finished_snapshots_tracker.update()

        with finished_snapshots_tracker:
            await asyncio.gather(*map(_delete_snapshot, snapshots_locations))

        finished_chunks_tracker = tqdm(
            desc='Unreferenced chunks deleted',
            unit='',
            total=len(to_delete),
            position=0,
            disable=self._quiet,
            leave=True,
        )

        async def _delete_chunk(digest):
            location = self._chunk_digest_to_location(digest)
            await self._delete(location)
            finished_chunks_tracker.update()

        with finished_chunks_tracker:
            await asyncio.gather(*map(_delete_chunk, to_delete))

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

        self.display_status('Fetching chunks list')
        async for location in self._abiter(self.backend.list_files, self.CHUNK_PREFIX):
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

        finished_tracker = tqdm(
            desc='Unreferenced chunks deleted',
            unit='',
            total=len(to_delete),
            position=0,
            disable=self._quiet,
            leave=True,
        )

        async def _delete_chunk(location):
            await self._delete(location)
            finished_tracker.update()

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

        adapter_type, adapter_args = utils.adapter_from_config(name=name, **settings)
        adapter = adapter_type(**adapter_args)
        argument_string = ', '.join(
            f'{name}={value!r}' for name, value in adapter_args.items()
        )
        self.display_status(f'Benchmarking {name}({argument_string})')
        benchmarker = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix='benchmarker'
        )

        if isinstance(adapter, ChunkerAdapter):
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(benchmarker, self._benchmark_chunker, adapter)
        else:
            raise RuntimeError('Sorry, not yet')

    async def upload(self, paths, *, rate_limit=None, skip_existing=False):
        self.display_status('Collecting files')
        files = self._flatten_paths(paths)
        logger.info('Found %d files', len(files))
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
        base_directory = Path.cwd()

        if rate_limit is not None:
            rate_limiter = utils.RateLimiter(rate_limit)
        else:
            rate_limiter = None

        async def _upload_path(path):
            name = path.relative_to(
                os.path.commonpath([path, base_directory])
            ).as_posix()
            length = path.stat().st_size

            if skip_existing and await self._exists(name):
                logger.info('Skipping file %r (exists)', name)
            else:
                async with self._acquire_slot() as slot:
                    logger.info('Uploading file %r', name)
                    stream = path.open('rb')
                    iowrapper = utils.tqdmio(
                        stream,
                        desc=name,
                        total=length,
                        position=slot,
                        disable=self._quiet,
                        rate_limiter=rate_limiter,
                    )
                    with stream, iowrapper:
                        await self._abwrap(
                            self.backend.upload_stream, name, iowrapper, length
                        )

            finished_tracker.update()
            bytes_tracker.update(length)

        await asyncio.gather(*map(_upload_path, files))
        return utils.DefaultNamespace(files=files)

    async def close(self):
        try:
            del self.props
        except AttributeError:
            pass

        await self._abwrap(self.backend.close)
