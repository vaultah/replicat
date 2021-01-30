import asyncio
import collections.abc
import functools
import inspect
import io
import json
import logging
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from functools import cached_property, partial
from pathlib import Path

from . import exceptions, utils

try:
    from tqdm import tqdm

    _tqdm_installed = True
except ImportError:
    # tqdm was not installed, and that's okay
    tqdm = None
    _tqdm_installed = False

logger = logging.getLogger(__name__)


@dataclass
class _chunk:
    _properties: utils.DefaultNamespace
    contents: bytes
    start: int
    end: int
    counter: int
    slot: int = None

    @cached_property
    def digest(self):
        return self._properties.digest(self.contents)

    @cached_property
    def encrypted_contents(self):
        if self._properties.encrypted:
            return self._properties.encrypt(
                self.contents, self._properties.derive_shared_key(self.digest)
            )
        else:
            return self.contents

    @cached_property
    def name(self):
        if self._properties.encrypted:
            return self._properties.mac(self.digest).hex()
        else:
            return self.digest.hex()

    @cached_property
    def location(self):
        return f'data/{self.name[:2]}/{self.name}'


class TrackedBytesIO(io.BytesIO):
    def __init__(self, initial_bytes, *, desc, slot, progress):
        super().__init__(initial_bytes)
        self.initial_bytes = initial_bytes

        if _tqdm_installed:
            self._tracker = tqdm(
                desc=desc,
                unit='B',
                total=len(initial_bytes),
                unit_scale=True,
                position=slot,
                file=sys.stdout,
                disable=not progress,
                leave=False,
            )
        else:
            self._tracker = None

    def read(self, *args, **kwargs):
        # TODO: rate limit
        data = super().read(*args, **kwargs)
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
    def __init__(self, backend, *, concurrent, progress=False):
        self._concurrent = concurrent
        self._slots = asyncio.Queue(maxsize=concurrent)
        # We need actual integers for TQDM slot management
        for slot in range(2, concurrent + 2):
            self._slots.put_nowait(slot)

        if progress and not _tqdm_installed:
            raise exceptions.ReplicatError(
                'TQDM is required to display progress '
                '(can be installed with [progress] or [all])'
            )

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
            self._executor = ThreadPoolExecutor(max_workers=self._slots.maxsize)
            return self._executor

    def serialize(self, object):
        string = json.dumps(object, separators=(',', ':'), default=utils.type_hint)
        return bytes(string, 'ascii')

    def deserialize(self, data):
        return json.loads(data, object_hook=utils.type_reverse)

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

    @cached_property
    def _chunk_type(self):
        return partial(_chunk, _properties=self.properties)

    def _config_and_key_from_settings(self, settings):
        # Create a raw and unencrypted combination of config and key, using
        # user-provided settings and our defaults
        config = {}
        key = None

        # Hashing algorithm for chunks
        hashing_config = settings.get('hashing', {})
        hashing_config.setdefault('name', 'blake2b')
        hasher, hasher_args = utils.adapter_from_config(**hashing_config)
        config['hashing'] = {'name': type(hasher).__name__, **hasher_args}
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
                    'chunker_personalization': chunker.chunking_params(),
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
            properties.derive_key = functools.partial(
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
            properties.mac = functools.partial(
                properties.authenticator.mac, params=private['mac_key']
            )
            # KDF for shared data
            properties.shared_kdf, _ = utils.adapter_from_config(
                **private['shared_kdf']
            )
            properties.derive_shared_key = functools.partial(
                properties.shared_kdf.derive, params=private['shared_encryption_secret']
            )
            # Chunking
            properties.chunkify = functools.partial(
                properties.chunker, params=private['chunker_personalization']
            )
        else:
            properties.chunkify = properties.chunker

        return properties

    async def unlock(self, *, password=None, key=None):
        print('Loading config...')
        data = await self.as_coroutine(self.backend.download, 'config')
        config = self.deserialize(data)

        # TODO: Load the key from the backend as a fallback?
        if isinstance(key, collections.abc.ByteString):
            key = self.deserialize(key)

        print('Unlocking repository...')
        self.properties = self._prepare_config(config, password=password, key=key)

    async def init(self, *, password=None, settings=None):
        if settings is None:
            settings = {}

        print('Generating config and key...')
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

    async def snapshot(self, *, paths):
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
            file=sys.stdout,
            disable=not self._progress,
            leave=True,
        )
        finished_tracker = tqdm(
            desc='Files processed',
            unit='',
            total=len(files),
            position=1,
            file=sys.stdout,
            disable=not self._progress,
            leave=True,
        )
        loop = asyncio.get_event_loop()
        tasks = set()
        chunk_queue = asyncio.Queue(maxsize=self._concurrent * 5)
        _stop = threading.Event()

        def _done_chunk(chunk: _chunk):
            logger.info('Chunk %s processed successfully', chunk.name)

            for file, ranges in state.file_ranges.items():
                if ranges is None:
                    continue

                file_start, file_end = ranges
                if file_start > chunk.end or file_end < chunk.start:
                    continue

                chunk_lo = max(file_start - chunk.start, 0)
                chunk_hi = min(file_end, chunk.end) - chunk.start

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

                if chunk.end >= file_end and file in state.files_finished:
                    # File completed
                    logger.info('File %r fully processed', str(file))
                    finished_tracker.update()

            bytes_tracker.update(chunk.end - chunk.start)

        async def _upload_chunk(chunk):
            io_wrapper = TrackedBytesIO(
                chunk.encrypted_contents,
                desc=f'Chunk #{chunk.counter:06}',
                slot=chunk.slot,
                progress=self._progress,
            )
            await self.as_coroutine(self.backend.upload, chunk.location, io_wrapper)
            _done_chunk(chunk)

        def _stream_files():
            for file, source_chunk in utils.fs.stream_files(files):
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

        def _chunk_generator():
            for output_chunk in self.properties.chunkify(_stream_files()):
                if _stop.is_set():
                    logging.debug('Stopping chunk generator')
                    return

                start = state.bytes_chunked
                state.bytes_chunked += len(output_chunk)
                asyncio.run_coroutine_threadsafe(
                    chunk_queue.put((start, output_chunk)), loop=loop
                )

        chunk_generator = loop.run_in_executor(
            ThreadPoolExecutor(max_workers=1), _chunk_generator
        )
        chunk_generator.add_done_callback(lambda fut: fut.result())

        while not chunk_queue.empty() or not chunk_generator.done():
            try:
                starts_at, output_chunk = chunk_queue.get_nowait()
            except asyncio.QueueEmpty:
                await asyncio.sleep(0.02)
                continue

            state.chunk_counter += 1
            slot = await self._slots.get()
            chunk = self._chunk_type(
                contents=output_chunk,
                counter=state.chunk_counter,
                start=starts_at,
                end=starts_at + len(output_chunk),
                slot=slot,
            )

            matching = await self.as_coroutine(self.backend.list_files, chunk.location)
            if next(iter(matching), None) is not None:
                logger.info('Will reuse chunk %s', chunk.name)
                try:
                    _done_chunk(chunk)
                except BaseException:
                    _stop.set()
                    raise
                else:
                    continue
                finally:
                    self._slots.put_nowait(slot)

            logger.info('Uploading chunk %s', chunk.name)
            task = asyncio.create_task(_upload_chunk(chunk))

            def cb(fut, slot=slot):
                try:
                    fut.result()
                except BaseException:
                    _stop.set()
                    raise
                else:
                    # Allow the chunk to be garbage-collected
                    tasks.discard(task)
                finally:
                    self._slots.put_nowait(slot)

            task.add_done_callback(cb)
            tasks.add(task)

        if tasks:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)

        now = datetime.utcnow()
        snapshot = {
            'utc_timestamp': str(now),
            'unix_timestamp': now.timestamp(),
            'files': list(snapshot_files.values()),
            # TODO: 'config'
        }
        logger.debug(
            'Generated snashot: %s',
            json.dumps(snapshot, indent=4, sort_keys=True, default=utils.type_hint),
        )
        encrypted_snapshot = self.properties.encrypt(
            self.serialize(snapshot), self.properties.userkey
        )
        snapshot_name = self.properties.digest(encrypted_snapshot).hex()
        await self.as_coroutine(
            self.backend.upload, f'snapshots/{snapshot_name}', encrypted_snapshot
        )
        return utils.DefaultNamespace(snapshot=snapshot_name, data=snapshot)
