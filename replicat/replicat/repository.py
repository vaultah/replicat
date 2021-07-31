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
import weakref
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from functools import partial
from pathlib import Path

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


class Repository:
    CHUNK_PREFIX = 'data/'
    SNAPSHOT_PREFIX = 'snapshots/'

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
        """ Executor for non-async methods of `backend` """
        try:
            return self._executor
        except AttributeError:
            self._executor = ThreadPoolExecutor(max_workers=self._concurrent)
            return self._executor

    def serialize(self, object):
        string = json.dumps(object, separators=(',', ':'), default=utils.type_hint)
        return bytes(string, 'ascii')

    def deserialize(self, data):
        return json.loads(data, object_hook=utils.type_reverse)

    def chunk_name_to_location(self, name):
        return os.path.join(self.CHUNK_PREFIX, name[:2], name)

    def chunk_location_to_name(self, location):
        _, tail = os.path.split(location)
        assert tail
        return tail

    def snapshot_name_to_location(self, name):
        return os.path.join(self.SNAPSHOT_PREFIX, name)

    def snapshot_location_to_name(self, location):
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

    def _config_and_key_from_settings(self, settings):
        # Create a raw and unencrypted combination of config and key, using
        # user-provided settings and our defaults
        config = {}
        key = None

        # Hashing algorithm for chunks
        hashing_config = settings.get('hashing', {})
        hashing_config.setdefault('name', 'blake2b')
        hasher, hasher_args = utils.adapter_from_config(**hashing_config)
        config['hashing'] = dict(hasher_args, name=type(hasher).__name__)

        # Deduplication params
        chunker = settings.get('chunking', {})
        chunker.setdefault('name', 'gclmulchunker')
        chunker, chunker_args = utils.adapter_from_config(**chunker)
        config['chunking'] = dict(chunker_args, name=type(chunker).__name__)

        encryption = settings.get('encryption', {})

        if encryption is not None:
            # Cipher for user data
            cipher_config = encryption.get('cipher', {})
            cipher_config.setdefault('name', 'aes_gcm')
            cipher, cipher_args = utils.adapter_from_config(**cipher_config)
            config['encryption'] = {
                'cipher': dict(cipher_args, name=type(cipher).__name__)
            }

            # KDF for user personal data
            kdf_config = encryption.get('kdf', {})
            kdf_config.setdefault('name', 'scrypt')
            kdf, kdf_args = utils.adapter_from_config(
                **kdf_config, length=cipher.key_bytes
            )

            # NOTE: *FAST* KDF for shared data. Yes, it's non-standard. Don't @ me.
            shared_config = encryption.get('shared_kdf', {})
            shared_config.setdefault('name', 'blake2b')
            shared_kdf, shared_args = utils.adapter_from_config(
                **shared_config, length=cipher.key_bytes
            )

            mac_config = encryption.get('mac', {})
            mac_config.setdefault('name', 'blake2b')
            mac, mac_args = utils.adapter_from_config(**mac_config)

            key = {
                'kdf': dict(kdf_args, name=type(kdf).__name__),
                'key_derivation_params': kdf.derivation_params(),
                'private': {
                    'shared_kdf': dict(shared_args, name=type(shared_kdf).__name__),
                    'mac': dict(mac_args, name=type(mac).__name__),
                    'shared_encryption_secret': shared_kdf.derivation_params(),
                    'mac_key': mac.mac_params(),
                    'chunker_secret': chunker.chunking_params(),
                },
            }

        return config, key

    def _prepare_config(self, config, *, password=None, key=None):
        properties = utils.DefaultNamespace()

        properties.chunker, _ = utils.adapter_from_config(**config['chunking'])
        properties.hasher, _ = utils.adapter_from_config(**config['hashing'])
        properties.digest = properties.hasher.digest

        encryption = config.get('encryption')
        # NOTE: only symmetric encryption is supported at this point anyway
        properties.encrypted = bool(encryption)

        if properties.encrypted:
            if password is None or key is None:
                raise exceptions.ReplicatError(
                    'Password and key are needed to unlock this repository'
                )

            # Encryption
            properties.cipher, _ = utils.adapter_from_config(**encryption['cipher'])
            properties.encrypt = properties.cipher.encrypt
            properties.decrypt = properties.cipher.decrypt

            # Key derivation
            properties.kdf, _ = utils.adapter_from_config(**key['kdf'])
            properties.derive_key = partial(
                properties.kdf.derive, params=key['key_derivation_params']
            )
            properties.userkey = properties.derive_key(password)

            try:
                private = key['private']
            except KeyError:
                # Private portion of the key is still encrypted
                decrypted_private = properties.decrypt(
                    key['encrypted'], properties.userkey
                )
                private = self.deserialize(decrypted_private)

            # Message authentication
            properties.authenticator, _ = utils.adapter_from_config(**private['mac'])
            properties.mac = partial(
                properties.authenticator.mac, params=private['mac_key']
            )
            # KDF for shared data
            properties.shared_kdf, _ = utils.adapter_from_config(
                **private['shared_kdf']
            )
            properties.derive_shared_key = partial(
                properties.shared_kdf.derive, params=private['shared_encryption_secret']
            )
            # Chunking
            properties.chunkify = partial(
                properties.chunker, params=private['chunker_secret']
            )
        else:
            properties.chunkify = properties.chunker

        return properties

    async def unlock(self, *, password=None, key=None):
        print('Loading config')
        data = await self.as_coroutine(self.backend.download, 'config')
        config = self.deserialize(data)

        # TODO: Load the key from the backend as a fallback?
        if isinstance(key, collections.abc.ByteString):
            key = self.deserialize(key)

        print('Unlocking repository')
        self.properties = self._prepare_config(config, password=password, key=key)

    async def init(self, *, password=None, settings=None):
        if settings is None:
            settings = {}

        print('Generating config and key')
        config, key = self._config_and_key_from_settings(utils.flat_to_nested(settings))
        self.properties = self._prepare_config(config, password=password, key=key)

        if self.properties.encrypted:
            logger.debug(
                'New key (unencrypted):\n%s',
                json.dumps(key, indent=4, default=utils.type_hint),
            )
            key['encrypted'] = self.properties.encrypt(
                self.serialize(key.pop('private')), self.properties.userkey
            )
            pretty_key = json.dumps(key, indent=4, default=utils.type_hint)
            # TODO: store in the repository?
            # TODO: warn on overwrite?
            key_path = Path('replicat.key').resolve()
            key_path.write_text(pretty_key)
            print(f'New key (stored in {key_path}):', pretty_key, sep='\n')

        await self.as_coroutine(self.backend.upload, 'config', self.serialize(config))
        pretty_config = json.dumps(
            config, indent=4, sort_keys=True, default=utils.type_hint
        )
        print('Generated config (stored in repository):', pretty_config, sep='\n')
        return utils.DefaultNamespace(config=config, key=key)

    async def _load_snapshots(self, *, snapshot_regex=None):
        snapshots = {}
        tasks = []
        semaphore = asyncio.Semaphore(self._concurrent)
        stored_snapshots = await self.as_coroutine(
            self.backend.list_files, self.SNAPSHOT_PREFIX
        )
        cached_snapshots = {str(x) for x in utils.fs.list_cached(self.SNAPSHOT_PREFIX)}

        async def _download_snapshot(path):
            async with semaphore:
                logger.info('Downloading %s', path)
                contents = await self.as_coroutine(self.backend.download, path)

            logger.info('Caching %s', path)
            utils.fs.store_cached(path, contents)
            if self.properties.encrypted:
                logger.info('Decrypting %s', path)
                snapshots[path] = self.deserialize(
                    self.properties.decrypt(contents, self.properties.userkey)
                )
            else:
                snapshots[path] = self.deserialize(contents)

        for snapshot_path in stored_snapshots:
            snapshot_name = self.snapshot_location_to_name(snapshot_path)
            if snapshot_regex is not None:
                if re.search(snapshot_regex, snapshot_name) is None:
                    continue

            if snapshot_path in cached_snapshots:
                contents = utils.fs.get_cached(snapshot_path)
                if self.properties.encrypted:
                    logger.info('%s is cached, decrypting', snapshot_path)
                    snapshots[snapshot_path] = self.deserialize(
                        self.properties.decrypt(contents, self.properties.userkey)
                    )
                else:
                    logger.info('%s is cached', snapshot_path)
                    snapshots[snapshot_path] = self.deserialize(contents)
                continue

            tasks.append(asyncio.create_task(_download_snapshot(snapshot_path)))

        if tasks:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)

        return snapshots

    async def list_snapshots(self, *, snapshot_regex=None):
        snapshots_mapping = await self._load_snapshots(snapshot_regex=snapshot_regex)
        if not snapshots_mapping:
            return

        snapshots = []
        for snapshot_path, snapshot_data in snapshots_mapping.items():
            snapshots.append(
                utils.DefaultNamespace(
                    snapshot_path=snapshot_path, snapshot=snapshot_data,
                )
            )

        snapshot_columns = {
            'snapshot': lambda x: self.snapshot_location_to_name(x.snapshot_path),
            'timestamp (utc)': lambda x: datetime.fromisoformat(
                x.snapshot['utc_timestamp']
            ).isoformat(sep=' ', timespec='seconds'),
            'files': lambda x: len(x.snapshot['files']),
            'size': lambda x: utils.bytes_to_human(
                sum(
                    chunk['end'] - chunk['start']
                    for file in x.snapshot['files']
                    for chunk in file['chunks']
                )
            ),
        }
        snapshots.sort(key=lambda x: x.snapshot['utc_timestamp'], reverse=True)
        columns = []

        for header, getter in snapshot_columns.items():
            max_length = max(len(str(getter(x))) for x in snapshots)
            columns.append(header.upper().center(max_length))

        print(*columns)
        for x in snapshots:
            print(*(g(x) for g in snapshot_columns.values()))

    async def list_files(self, *, snapshot_regex=None, files_regex=None):
        snapshots_mapping = await self._load_snapshots(snapshot_regex=snapshot_regex)
        if not snapshots_mapping:
            return

        files = []
        for snapshot_path, snapshot_data in snapshots_mapping.items():
            for file_data in snapshot_data['files']:
                if files_regex is not None:
                    if re.search(files_regex, file_data['path']) is None:
                        continue

                files.append(
                    utils.DefaultNamespace(
                        snapshot_path=snapshot_path,
                        snapshot=snapshot_data,
                        file=file_data,
                    )
                )

        if not files:
            return

        file_columns = {
            'snapshot date': lambda x: datetime.fromisoformat(
                x.snapshot['utc_timestamp']
            ).isoformat(sep=' ', timespec='seconds'),
            'path': lambda x: x.file['path'],
            'chunks count': lambda x: len(x.file['chunks']),
            'size': lambda x: sum(y['end'] - y['start'] for y in x.file['chunks']),
        }
        files.sort(key=lambda x: x.snapshot['utc_timestamp'], reverse=True)
        columns = []
        for header, getter in file_columns.items():
            max_length = max(len(str(getter(x))) for x in files)
            columns.append(header.upper().center(max_length))

        print(*columns)
        for x in files:
            print(*(g(x) for g in file_columns.values()))

    async def snapshot(self, *, paths, rate_limit=None):
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
        tasks = weakref.WeakSet()
        chunk_queue = queue.Queue(maxsize=self._concurrent * 10)
        abort = threading.Event()

        if rate_limit is not None:
            rate_limiter = _RateLimiter(rate_limit)
        else:
            rate_limiter = None

        def _done_chunk(chunk: _Chunk):
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

        async def _upload_chunk(chunk: _Chunk, slot):
            try:
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
                _done_chunk(chunk)
            except BaseException:
                abort.set()
                raise
            finally:
                self._slots.put_nowait(slot)

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

        def _chunk_producer():
            for output_chunk in self.properties.chunkify(_stream_files()):
                if abort.is_set():
                    logging.debug('Stopping chunk producer')
                    return

                state.chunk_counter += 1
                stream_start = state.bytes_chunked
                state.bytes_chunked += len(output_chunk)
                digest = self.properties.digest(output_chunk)

                if self.properties.encrypted:
                    encrypted_contents = self.properties.encrypt(
                        output_chunk, self.properties.derive_shared_key(digest)
                    )
                    name = self.properties.mac(digest).hex()
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
                chunk_queue.put(chunk)

        chunk_producer = loop.run_in_executor(
            ThreadPoolExecutor(max_workers=1, thread_name_prefix='chunk-producer'),
            _chunk_producer,
        )
        while not chunk_queue.empty() or not chunk_producer.done():
            try:
                chunk = chunk_queue.get_nowait()
            except queue.Empty:
                await asyncio.sleep(0.025)
                continue

            slot = await self._slots.get()
            if await self.as_coroutine(
                self.backend.exists, self.chunk_name_to_location(chunk.name)
            ):
                logger.info('Will reuse chunk %s', chunk.name)
                try:
                    _done_chunk(chunk)
                except BaseException:
                    abort.set()
                    raise
                else:
                    continue
                finally:
                    self._slots.put_nowait(slot)

            logger.info('Uploading chunk %s', chunk.name)
            task = asyncio.create_task(_upload_chunk(chunk, slot))
            task.add_done_callback(lambda fut: fut.result())
            tasks.add(task)

        await chunk_producer
        if tasks:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)

        now = datetime.utcnow()
        snapshot_data = {
            'utc_timestamp': str(now),
            'unix_timestamp': now.timestamp(),
            'files': list(snapshot_files.values()),
            # TODO: 'config'
        }
        logger.debug(
            'Generated snashot: %s',
            json.dumps(
                snapshot_data, indent=4, sort_keys=True, default=utils.type_hint
            ),
        )
        if self.properties.encrypted:
            encrypted_snapshot = self.properties.encrypt(
                self.serialize(snapshot_data), self.properties.userkey
            )
        else:
            encrypted_snapshot = self.serialize(snapshot_data)

        snapshot_name = self.properties.digest(encrypted_snapshot).hex()

        await self.as_coroutine(
            self.backend.upload,
            self.snapshot_name_to_location(snapshot_name),
            encrypted_snapshot,
        )
        return utils.DefaultNamespace(snapshot=snapshot_name, data=snapshot_data)

    async def restore(self, *, snapshot_regex=None, files_regex=None):
        snapshots_mapping = await self._load_snapshots(snapshot_regex=snapshot_regex)
        ordered_snapshots = sorted(
            snapshots_mapping.values(), key=lambda x: x['utc_timestamp'], reverse=True
        )
        chunk_mapping = {}
        tasks = weakref.WeakSet()
        executor = ThreadPoolExecutor(
            max_workers=self._concurrent * 5, thread_name_prefix='file-writer'
        )
        glock = threading.Lock()
        flocks = {}
        loop = asyncio.get_event_loop()
        seen_files = set()
        total_bytes = 0

        def _write_chunk_ref(ref, contents):
            with glock:
                try:
                    flock = flocks[ref.path]
                except KeyError:
                    flock = flocks[ref.path] = threading.Lock()

            with flock:
                ref.path.parent.mkdir(parents=True, exist_ok=True)
                ref.path.touch()

                with ref.path.open('r+b') as file:
                    file_end = file.seek(0, io.SEEK_END)
                    file.truncate(max(file_end, ref.stream_end))
                    file.seek(ref.stream_start)
                    file.write(contents[ref.start : ref.end])

            with glock:
                flocks.pop(ref.path, None)
                bytes_tracker.update(ref.end - ref.start)

        async def _download_chunk(name, *, slot):
            try:
                logger.info('Downloading chunk %s', name)
                contents = await self.as_coroutine(
                    self.backend.download, self.chunk_name_to_location(name)
                )
                if self.properties.encrypted:
                    decrypted_contents = self.properties.decrypt(
                        contents,
                        self.properties.derive_shared_key(chunk_mapping[name].digest),
                    )
                else:
                    decrypted_contents = contents

                decrypted_view = memoryview(decrypted_contents)
                await asyncio.gather(
                    *(
                        loop.run_in_executor(
                            executor, _write_chunk_ref, ref, decrypted_view
                        )
                        for ref in chunk_mapping[name].refs
                    )
                )
            finally:
                self._slots.put_nowait(slot)

        for snapshot_data in ordered_snapshots:
            for file_data in snapshot_data['files']:
                if file_data['path'] in seen_files:
                    continue

                if files_regex is not None:
                    if re.search(files_regex, file_data['path']) is None:
                        continue

                restore_to = Path(*Path(file_data['path']).parts[1:]).resolve()
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
        for chunk_name in chunk_mapping:
            slot = await self._slots.get()
            task = asyncio.create_task(_download_chunk(chunk_name, slot=slot))
            task.add_done_callback(lambda fut: fut.result())
            tasks.add(task)

        if tasks:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)

    async def close(self):
        # Closes associated resources
        if inspect.iscoroutinefunction(self.backend.close):
            await self.backend.close()
        else:
            self.backend.close()

        del self.properties
