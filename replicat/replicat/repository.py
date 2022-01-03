import asyncio
import collections.abc
import inspect
import io
import json
import logging
import os
import queue
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from functools import partial
from pathlib import Path

from sty import ef
from tqdm import tqdm

from . import exceptions, utils

logger = logging.getLogger(__name__)


class _RateLimiter:
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


@dataclass(frozen=True)
class _Chunk:
    contents: bytes
    digest: bytes
    name: str
    stream_start: int
    stream_end: int
    counter: int


class _TrackedBytesIO(io.BytesIO):
    def __init__(self, initial_bytes, *, desc, slot, progress, rate_limiter):
        super().__init__(initial_bytes)
        self.initial_bytes = initial_bytes
        self.rate_limiter = rate_limiter
        self._tracker = tqdm(
            desc=desc,
            unit='B',
            total=len(initial_bytes),
            unit_scale=True,
            position=slot,
            disable=not progress,
            leave=False,
        )

    def read(self, size):
        if self.rate_limiter is not None:
            size = min(max(self.rate_limiter.available(), 1), size, 16_384)
            data = super().read(size)
            self.rate_limiter.consumed(len(data))
        else:
            data = super().read(size)

        if self._tracker is not None:
            self._tracker.update(len(data))

        return data

    def seek(self, *args, **kwargs):
        pos = super().seek(*args, **kwargs)
        if self._tracker is not None:
            self._tracker.reset()
            self._tracker.update(pos)

    def write(self, *args, **kwargs):
        raise NotImplementedError

    def iter_chunks(self, chunk_size=128_000):
        yield from iter(lambda: self.read(chunk_size), b'')

    def __len__(self):
        return len(self.initial_bytes)

    def __iter__(self):
        return self.iter_chunks()

    async def __aiter__(self):
        # For compatibility with httpx
        for x in self.iter_chunks():
            yield x


class RepositoryProps(utils.DefaultNamespace):
    def merge(self, other):
        if not isinstance(other, RepositoryProps):
            raise TypeError
        self.__dict__.update(other.__dict__)

    __repr__ = object.__repr__


class Repository:
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

    def __init__(self, backend, *, concurrent, progress=False):
        self._concurrent = concurrent
        self._slots = asyncio.Queue(maxsize=concurrent)
        # We need actual integers for TQDM slot management
        for slot in range(2, concurrent + 2):
            self._slots.put_nowait(slot)

        self._progress = progress
        self.backend = backend

    def as_coroutine(self, func, *args, **kwargs):
        if inspect.iscoroutinefunction(func):
            return func(*args, **kwargs)
        else:
            loop = asyncio.get_event_loop()
            return loop.run_in_executor(self.executor, func, *args, **kwargs)

    @property
    def executor(self):
        """Executor for non-async methods of the backend instance"""
        try:
            return self._executor
        except AttributeError:
            self._executor = ThreadPoolExecutor(max_workers=self._concurrent)
            return self._executor

    def default_serialization_hook(self, data):
        return utils.type_hint(data)

    def serialize(self, object):
        string = json.dumps(
            object, separators=(',', ':'), default=self.default_serialization_hook
        )
        return bytes(string, 'ascii')

    def object_deserialization_hook(self, data):
        return utils.type_reverse(data)

    def deserialize(self, data):
        return json.loads(data, object_hook=self.object_deserialization_hook)

    def chunk_name_to_location(self, name):
        return os.path.join(self.CHUNK_PREFIX, name[:2], name)

    def chunk_location_to_name(self, location):
        if not location.startswith(self.CHUNK_PREFIX):
            raise ValueError('Not a chunk location')

        _, tail = os.path.split(location)
        assert tail
        return tail

    def snapshot_name_to_location(self, name):
        return os.path.join(self.SNAPSHOT_PREFIX, name)

    def snapshot_location_to_name(self, location):
        if not location.startswith(self.SNAPSHOT_PREFIX):
            raise ValueError('Not a snapshot location')

        _, tail = os.path.split(location)
        assert tail
        return tail

    def read_metadata(self, path):
        # TODO: Cache stat result?
        stat_result = os.stat(path)
        return {
            'st_mode': stat_result.st_mode,
            'st_uid': stat_result.st_uid,
            'st_gid': stat_result.st_gid,
            'st_size': stat_result.st_size,
            'st_atime': stat_result.st_atime,
            'st_mtime': stat_result.st_mtime,
            'st_ctime': stat_result.st_ctime,
        }

    def _make_config(self, *, settings=None):
        if settings is None:
            settings = {}

        config = {}

        # Hashing algorithm for chunks
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
        props = RepositoryProps()

        chunker_type, chunker_args = utils.adapter_from_config(**config['chunking'])
        props.chunker = chunker_type(**chunker_args)

        hasher_type, hasher_args = utils.adapter_from_config(**config['hashing'])
        props.hash_digest = hasher_type(**hasher_args).digest

        if (encryption_config := config.get('encryption')) is not None:
            cipher_type, cipher_args = utils.adapter_from_config(
                **encryption_config['cipher']
            )
            props.cipher = cipher_type(**cipher_args)
            props.encrypt = props.cipher.encrypt
            props.decrypt = props.cipher.decrypt
            # NOTE: only symmetric encryption is supported at this point anyway
            props.encrypted = True
        else:
            props.encrypted = False

        return props

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
                'shared_kdf': dict(shared_args, name=shared_kdf_type.__name__),
                'shared_encryption_secret': shared_kdf.derivation_params(),
                'mac': dict(mac_args, name=mac_type.__name__),
                'mac_key': mac.mac_params(),
                'chunker_secret': chunker.chunking_params(),
            }

        return {
            'kdf': dict(user_kdf_args, name=user_kdf_type.__name__),
            'key_derivation_params': user_kdf.derivation_params(),
            'private': private,
        }

    def _instantiate_key(self, key, *, password, cipher):
        props = RepositoryProps()

        # User key derivation
        kdf_type, kdf_args = utils.adapter_from_config(**key['kdf'])
        props.derive_user_key = partial(
            kdf_type(**kdf_args).derive, params=key['key_derivation_params']
        )
        props.userkey = props.derive_user_key(password)

        try:
            private = key['private']
        except KeyError:
            # Private portion of the key is still encrypted
            private = self.deserialize(cipher.decrypt(key['encrypted'], props.userkey))

        # Message authentication
        mac_type, mac_args = utils.adapter_from_config(**private['mac'])
        props.mac = partial(mac_type(**mac_args).mac, params=private['mac_key'])

        # KDF for shared data
        shared_kdf_type, shared_kdf_args = utils.adapter_from_config(
            **private['shared_kdf']
        )
        props.derive_shared_key = partial(
            shared_kdf_type(**shared_kdf_args).derive,
            params=private['shared_encryption_secret'],
        )
        props.chunker_params = private['chunker_secret']
        props.private = private
        return props

    async def init(self, *, password=None, settings=None, key_output_path=None):
        logger.info('Using provided settings: %r', settings)
        print(ef.bold + 'Generating config and key' + ef.rs)
        config = self._make_config(settings=settings)
        props = self._instantiate_config(config)

        if props.encrypted:
            if password is None:
                raise exceptions.ReplicatError(
                    'A password is needed to initialize encrypted repository'
                )

            key = self._make_key(
                cipher=props.cipher, chunker=props.chunker, settings=settings
            )
            props.merge(
                self._instantiate_key(key, password=password, cipher=props.cipher)
            )
            private = key.pop('private')
            logger.debug('Private key portion (unencrypted): %r', private)
            key['encrypted'] = props.encrypt(self.serialize(private), props.userkey)

            # TODO: store keys in the repository?
            if key_output_path is not None:
                key_output_path = Path(key_output_path).resolve()
                key_output_path.write_bytes(self.serialize(key))
                print(ef.bold + f'Generated key saved to {key_output_path}' + ef.rs)
            else:
                pretty_key = json.dumps(
                    key, indent=4, default=self.default_serialization_hook
                )
                print(ef.bold + 'New key:' + ef.rs, pretty_key, sep='\n')
        else:
            key = None

        await self.as_coroutine(self.backend.upload, 'config', self.serialize(config))
        self.props = props
        pretty_config = json.dumps(
            config, indent=4, default=self.default_serialization_hook
        )
        print(
            ef.bold + 'Generated config (stored in repository):' + ef.rs,
            pretty_config,
            sep='\n',
        )
        return utils.DefaultNamespace(config=config, key=key)

    async def unlock(self, *, password=None, key=None):
        print(ef.bold + 'Loading config' + ef.rs)
        data = await self.as_coroutine(self.backend.download, 'config')
        config = self.deserialize(data)
        props = self._instantiate_config(config)

        if props.encrypted:
            print(ef.bold + 'Unlocking repository' + ef.rs)
            if password is None or key is None:
                raise exceptions.ReplicatError(
                    'Both password and key are needed to unlock this repository'
                )

            # TODO: Load keys from the backend as a fallback?
            if isinstance(key, collections.abc.ByteString):
                key = self.deserialize(key)

            props.merge(
                self._instantiate_key(key, password=password, cipher=props.cipher)
            )

        self.props = props

    async def add_key(
        self, *, password, settings=None, shared=False, key_output_path=None
    ):
        if not self.props.encrypted:
            raise exceptions.ReplicatError('Repository is not encrypted')

        if password is None:
            raise exceptions.ReplicatError(
                'The password is required to generate a new key'
            )

        logger.info('Using provided settings: %r', settings)
        private = self.props.private if shared else None
        key = self._make_key(
            cipher=self.props.cipher,
            chunker=self.props.chunker,
            settings=settings,
            private=private,
        )
        key_props = self._instantiate_key(
            key, password=password, cipher=self.props.cipher
        )

        private = key.pop('private')
        logger.debug('Private portion of the new key (unencrypted): %r', private)
        key['encrypted'] = self.props.encrypt(
            self.serialize(private),
            key_props.userkey,
        )

        # TODO: store it in the repository?
        if key_output_path is not None:
            key_output_path = Path(key_output_path).resolve()
            key_output_path.write_bytes(self.serialize(key))
            print(ef.bold + f'Generated key saved to {key_output_path}' + ef.rs)
        else:
            pretty_key = json.dumps(
                key, indent=4, default=self.default_serialization_hook
            )
            print(ef.bold + 'New key:' + ef.rs, pretty_key, sep='\n')

        return utils.DefaultNamespace(new_key=key)

    async def _load_snapshots(self, *, snapshot_regex=None, cache_loaded=True):
        snapshots = {}
        tasks = []
        semaphore = asyncio.Semaphore(self._concurrent)
        stored_snapshots = await self.as_coroutine(
            self.backend.list_files, self.SNAPSHOT_PREFIX
        )
        cached_snapshots = {str(x) for x in utils.fs.list_cached(self.SNAPSHOT_PREFIX)}
        encrypted_snapshots = {}

        async def _download_snapshot(path):
            async with semaphore:
                logger.info('Downloading %s', path)
                contents = await self.as_coroutine(self.backend.download, path)

            snapshot_name = self.snapshot_location_to_name(path)
            if snapshot_name != self.props.hash_digest(contents).hex():
                raise exceptions.ReplicatError(
                    f'Snapshot {snapshot_name!r} is corrupted'
                )

            if cache_loaded:
                logger.info('Caching encrypted snapshot %s', path)
                utils.fs.store_cached(path, contents)

            encrypted_snapshots[path] = contents

        for snapshot_path in stored_snapshots:
            if snapshot_regex is not None:
                snapshot_name = self.snapshot_location_to_name(snapshot_path)
                if re.search(snapshot_regex, snapshot_name) is None:
                    continue

            if snapshot_path in cached_snapshots:
                contents = utils.fs.get_cached(snapshot_path)
                encrypted_snapshots[snapshot_path] = contents
                continue

            tasks.append(asyncio.create_task(_download_snapshot(snapshot_path)))

        if tasks:
            await asyncio.gather(*tasks)

        for path, contents in encrypted_snapshots.items():
            if self.props.encrypted:
                logger.info('Decrypting %s', path)
                try:
                    decrypted = self.props.decrypt(contents, self.props.userkey)
                except exceptions.DecryptionError:
                    logger.info(
                        "Decryption of %s failed, but it's not corrupted (different key?)",
                        path,
                    )
                    snapshots[path] = None
                else:
                    snapshots[path] = self.deserialize(decrypted)
            else:
                snapshots[path] = self.deserialize(contents)

        return snapshots

    def _format_snapshot_name(self, path, data):
        return self.snapshot_location_to_name(path)

    def _format_snapshot_note(self, path, data):
        if data is None:
            return None
        return data.get('note')

    def _format_snapshot_utc_timestamp(self, path, data):
        if data is None:
            return None

        dt = datetime.fromisoformat(data['utc_timestamp'])
        return dt.isoformat(sep=' ', timespec='seconds')

    def _format_snapshot_files_count(self, path, data):
        if data is None:
            return None

        return len(data['files'])

    def _format_snaphot_size(self, path, data):
        if data is None:
            return None

        return utils.bytes_to_human(
            sum(
                chunk['end'] - chunk['start']
                for file in data['files']
                for chunk in file['chunks']
            )
        )

    async def list_snapshots(self, *, snapshot_regex=None):
        snapshots_mapping = await self._load_snapshots(snapshot_regex=snapshot_regex)
        if not snapshots_mapping:
            return

        columns_getters = {
            'snapshot': self._format_snapshot_name,
            'note': self._format_snapshot_note,
            'timestamp (utc)': self._format_snapshot_utc_timestamp,
            'files': self._format_snapshot_files_count,
            'size': self._format_snaphot_size,
        }
        columns_widths = {}
        sorted_snapshots = sorted(
            snapshots_mapping.items(),
            key=lambda x: x[1]['utc_timestamp'] if x[1] is not None else '',
            reverse=True,
        )
        rows = []

        for path, snapshot in sorted_snapshots:
            row = {}
            for column, getter in columns_getters.items():
                value = getter(path, snapshot)
                if value is None:
                    value = self.EMPTY_TABLE_VALUE
                value = str(value)
                row[column] = value
                columns_widths[column] = max(len(value), columns_widths.get(column, 0))

            rows.append(row)

        formatted_headers = []
        for column in columns_widths:
            width = columns_widths[column] = max(len(column), columns_widths[column])
            formatted_headers.append(column.upper().center(width))

        print(*formatted_headers)
        for row in rows:
            print(*(value.ljust(columns_widths[col]) for col, value in row.items()))

    def _format_file_snapshot_date(self, snapshot_path, snapshot_data, file_data):
        dt = datetime.fromisoformat(snapshot_data['utc_timestamp'])
        return dt.isoformat(sep=' ', timespec='seconds')

    def _format_file_path(self, snapshot_path, snapshot_data, file_data):
        return file_data['path']

    def _format_file_chunks_count(self, snapshot_path, snapshot_data, file_data):
        return len(file_data['chunks'])

    def _format_file_size(self, snapshot_path, snapshot_data, file_data):
        return utils.bytes_to_human(
            sum(cd['end'] - cd['start'] for cd in file_data['chunks'])
        )

    async def list_files(self, *, snapshot_regex=None, files_regex=None):
        snapshots_mapping = await self._load_snapshots(snapshot_regex=snapshot_regex)
        if not snapshots_mapping:
            return

        columns_getters = {
            'snapshot date': self._format_file_snapshot_date,
            'path': self._format_file_path,
            'chunks count': self._format_file_chunks_count,
            'size': self._format_file_size,
        }
        columns_widths = {}
        files = []

        for snapshot_path, snapshot_data in snapshots_mapping.items():
            if snapshot_data is None:
                continue

            for file_data in snapshot_data['files']:
                if files_regex is not None:
                    if re.search(files_regex, file_data['path']) is None:
                        continue

                row = {}
                for column, getter in columns_getters.items():
                    value = getter(snapshot_path, snapshot_data, file_data)
                    if value is None:
                        value = self.EMPTY_TABLE_VALUE
                    value = str(value)
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

        print(*formatted_headers)
        for _, row in files:
            print(*(value.ljust(columns_widths[col]) for col, value in row.items()))

    async def snapshot(self, *, paths, note=None, rate_limit=None):
        files = []

        for path in utils.fs.flatten_paths(paths, follow_symlinks=True):
            try:
                path.resolve(strict=True)
            except (FileNotFoundError, RuntimeError):
                logger.warning('Skipping file %s, path not resolved', path)
            else:
                files.append(path)

        logger.info('Found %d files', len(files))
        # Small files are more likely to change than big files, read them quickly
        # and put them in chunks together
        files.sort(key=lambda file: (file.stat().st_size, str(file)))

        state = utils.DefaultNamespace(
            bytes_read=0,
            bytes_chunked=0,
            chunk_counter=0,
            # Fixed-size dictionary for thread safety
            file_ranges=dict.fromkeys(files),
            files_finished=set(),
            current_file=None,
        )
        snapshot_files = {}
        bytes_tracker = tqdm(
            desc='Data processed',
            unit='B',
            unit_scale=True,
            total=None,
            position=0,
            disable=not self._progress,
            leave=True,
        )
        finished_tracker = tqdm(
            desc='Files processed',
            unit='',
            total=len(files),
            position=1,
            disable=not self._progress,
            leave=True,
        )
        loop = asyncio.get_event_loop()
        chunk_queue = queue.Queue(maxsize=self._concurrent * 10)
        abort = threading.Event()

        if rate_limit is not None:
            rate_limiter = _RateLimiter(rate_limit)
        else:
            rate_limiter = None

        def _chunk_done(chunk: _Chunk):
            logger.info('Chunk %s processed successfully', chunk.name)

            for file, ranges in state.file_ranges.items():
                if ranges is None:
                    continue

                file_start, file_end = ranges
                if file_start > chunk.stream_end or file_end < chunk.stream_start:
                    continue

                chunk_lo = max(file_start - chunk.stream_start, 0)
                chunk_hi = min(file_end, chunk.stream_end) - chunk.stream_start

                if file not in snapshot_files:
                    snapshot_files[file] = {
                        'name': file.name,
                        'path': str(file.resolve()),
                        'chunks': [],
                        'metadata': self.read_metadata(file),
                    }

                snapshot_files[file]['chunks'].append(
                    {
                        'name': chunk.name,
                        'start': chunk_lo,
                        'end': chunk_hi,
                        'digest': chunk.digest.hex(),
                        'counter': chunk.counter,
                    }
                )

                if chunk.stream_end >= file_end and file in state.files_finished:
                    # File completed
                    logger.info('File %r fully processed', str(file))
                    finished_tracker.update()

            bytes_tracker.update(chunk.stream_end - chunk.stream_start)

        def _stream_files():
            with utils.fs.stream_files(files) as stream:
                for file, source_chunk in stream:
                    if state.file_ranges[file] is None:
                        logger.debug('Started streaming file %r', str(file))
                        # First chunk from this file
                        start = state.bytes_read
                        if state.current_file is not None:
                            logger.debug(
                                'Finished streaming file %r', str(state.current_file)
                            )
                            state.files_finished.add(state.current_file)

                        state.current_file = file
                    else:
                        start, _ = state.file_ranges[file]

                    state.bytes_read += len(source_chunk)
                    state.file_ranges[file] = (start, state.bytes_read)
                    yield source_chunk

            if state.current_file is not None:
                logger.debug(
                    'Finished streaming file %r (last)', str(state.current_file)
                )
                state.files_finished.add(state.current_file)

        def _chunk_producer(queue_timeout=0.025):
            # Will run in a different thread, since most of these actions release GIL
            for output_chunk in self.props.chunker(
                _stream_files(), params=self.props.chunker_params
            ):
                state.chunk_counter += 1
                stream_start = state.bytes_chunked
                state.bytes_chunked += len(output_chunk)
                digest = self.props.hash_digest(output_chunk)

                if self.props.encrypted:
                    encrypted_contents = self.props.encrypt(
                        output_chunk, self.props.derive_shared_key(digest)
                    )
                    name = self.props.mac(digest).hex()
                else:
                    encrypted_contents = output_chunk
                    name = digest.hex()

                chunk = _Chunk(
                    contents=encrypted_contents,
                    digest=digest,
                    name=name,
                    counter=state.chunk_counter,
                    stream_start=stream_start,
                    stream_end=stream_start + len(output_chunk),
                )
                while True:
                    if abort.is_set():
                        logging.debug('Stopping chunk producer')
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

                slot = await self._slots.get()
                try:
                    if await self.as_coroutine(
                        self.backend.exists, self.chunk_name_to_location(chunk.name)
                    ):
                        logger.info('Will reuse existing chunk %s', chunk.name)
                    else:
                        logger.info('Will upload new chunk %s', chunk.name)
                        io_wrapper = _TrackedBytesIO(
                            chunk.contents,
                            desc=f'Chunk #{chunk.counter:06}',
                            slot=slot,
                            progress=self._progress,
                            rate_limiter=rate_limiter,
                        )
                        await self.as_coroutine(
                            self.backend.upload,
                            self.chunk_name_to_location(chunk.name),
                            io_wrapper,
                        )

                    _chunk_done(chunk)
                finally:
                    self._slots.put_nowait(slot)

        chunk_producer = loop.run_in_executor(
            ThreadPoolExecutor(max_workers=1, thread_name_prefix='chunk-producer'),
            _chunk_producer,
        )
        try:
            await asyncio.gather(*(_worker() for _ in range(self._concurrent)))
        except BaseException:
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

        logger.debug(
            'Generated snashot: %s',
            json.dumps(
                snapshot_data,
                indent=4,
                sort_keys=True,
                default=self.default_serialization_hook,
            ),
        )
        if self.props.encrypted:
            encrypted_snapshot = self.props.encrypt(
                self.serialize(snapshot_data), self.props.userkey
            )
        else:
            encrypted_snapshot = self.serialize(snapshot_data)

        snapshot_name = self.props.hash_digest(encrypted_snapshot).hex()

        await self.as_coroutine(
            self.backend.upload,
            self.snapshot_name_to_location(snapshot_name),
            encrypted_snapshot,
        )
        return utils.DefaultNamespace(name=snapshot_name, data=snapshot_data)

    async def restore(self, *, snapshot_regex=None, files_regex=None, path=None):
        if path is None:
            path = Path().resolve()
        else:
            path = path.resolve()

        logger.info("Will restore files to %s", path)

        snapshots_mapping = await self._load_snapshots(snapshot_regex=snapshot_regex)
        snapshots = [x for x in snapshots_mapping.values() if x is not None]
        snapshots.sort(key=lambda x: x['utc_timestamp'], reverse=True)

        chunk_mapping = {}
        executor = ThreadPoolExecutor(
            max_workers=self._concurrent * 5, thread_name_prefix='file-writer'
        )
        glock = threading.Lock()
        flocks = {}
        flocks_refcounts = {}
        loop = asyncio.get_event_loop()
        seen_files = set()
        total_bytes = 0

        def _write_chunk_ref(ref, contents):
            with glock:
                try:
                    flock = flocks[ref.path]
                except KeyError:
                    flock = flocks[ref.path] = threading.Lock()
                    flocks_refcounts[ref.path] = 1
                else:
                    flocks_refcounts[ref.path] += 1

            with flock:
                ref.path.parent.mkdir(parents=True, exist_ok=True)
                ref.path.touch()

                with ref.path.open('r+b') as file:
                    file_end = file.seek(0, io.SEEK_END)
                    file.truncate(max(file_end, ref.stream_end))
                    file.seek(ref.stream_start)
                    file.write(contents[ref.start : ref.end])

            with glock:
                bytes_tracker.update(ref.end - ref.start)
                flocks_refcounts[ref.path] -= 1
                if not flocks_refcounts[ref.path]:
                    del flocks_refcounts[ref.path], flocks[ref.path]

        async def _worker():
            while True:
                try:
                    name, data = chunk_mapping.popitem()
                except KeyError:
                    break

                slot = await self._slots.get()
                try:
                    logger.info('Downloading chunk %s', name)
                    contents = await self.as_coroutine(
                        self.backend.download, self.chunk_name_to_location(name)
                    )
                    digest = data.digest
                    if self.props.encrypted:
                        decrypted_contents = self.props.decrypt(
                            contents,
                            self.props.derive_shared_key(digest),
                        )
                    else:
                        decrypted_contents = contents

                    if digest != self.props.hash_digest(decrypted_contents):
                        raise exceptions.ReplicatError(f'Chunk {name} is corrupted')

                    decrypted_view = memoryview(decrypted_contents)
                    await asyncio.gather(
                        *(
                            loop.run_in_executor(
                                executor, _write_chunk_ref, ref, decrypted_view
                            )
                            for ref in data.refs
                        )
                    )
                finally:
                    self._slots.put_nowait(slot)

        for snapshot_data in snapshots:
            for file_data in snapshot_data['files']:
                if file_data['path'] in seen_files:
                    continue

                if files_regex is not None:
                    if re.search(files_regex, file_data['path']) is None:
                        continue

                restore_to = Path(path, *Path(file_data['path']).parts[1:]).resolve()
                ordered_chunks = sorted(file_data['chunks'], key=lambda x: x['counter'])
                chunk_position = 0

                for chunk_data in ordered_chunks:
                    try:
                        data = chunk_mapping[chunk_data['name']]
                    except KeyError:
                        new = utils.DefaultNamespace(
                            digest=bytes.fromhex(chunk_data['digest']), refs=[]
                        )
                        data = chunk_mapping[chunk_data['name']] = new

                    chunk_size = chunk_data['end'] - chunk_data['start']
                    data.refs.append(
                        utils.DefaultNamespace(
                            path=restore_to,
                            stream_start=chunk_position,
                            stream_end=chunk_position + chunk_size,
                            start=chunk_data['start'],
                            end=chunk_data['end'],
                        )
                    )
                    chunk_position += chunk_size

                total_bytes += chunk_position
                seen_files.add(file_data['path'])

        bytes_tracker = tqdm(
            desc='Data processed',
            unit='B',
            unit_scale=True,
            total=total_bytes,
            position=0,
            disable=not self._progress,
            leave=True,
        )
        await asyncio.gather(*(_worker() for _ in range(self._concurrent)))
        return utils.DefaultNamespace(files=list(seen_files))

    async def close(self):
        # Closes associated resources
        if inspect.iscoroutinefunction(self.backend.close):
            await self.backend.close()
        else:
            self.backend.close()

        del self.props
