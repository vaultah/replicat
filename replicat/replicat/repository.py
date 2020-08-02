import asyncio
import base64
import collections.abc
import functools
import inspect
import json
import logging
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from . import utils
from . import exceptions

logger = logging.getLogger(__name__)


class Repository:

    def __init__(self, backend, *, concurrent, progress=False):
        self._slots = asyncio.Queue(maxsize=concurrent)
        # We need actual integers for TQDM slot management
        for x in range(concurrent):
            self._slots.put_nowait(x)
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

    def _make_config(self, settings):
        # Create a raw and unencrypted combination of config and key, using
        # user-provided settings and our defaults
        config = {}
        encryption = settings.get('encryption', {})

        if encryption is not None:
            # Cipher for user data
            cipher_config = encryption.get('cipher', {})
            cipher_config.setdefault('name', 'aes_gcm')
            cipher, cipher_args = utils.adapter_from_config(**cipher_config)

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

            chunker = settings.get('chunking', {})
            chunker.setdefault('name', 'simple_chunker')
            chunker, chunker_args = utils.adapter_from_config(**chunker)

            config['encryption'] = {
                'cipher': {'name': type(cipher).__name__, **cipher_args}
            }

            config['key'] = {
                'kdf': {'name': type(kdf).__name__, **kdf_args},
                'key_derivation_params': kdf.derivation_params(),
                'private': {
                    'shared_kdf': {'name': type(shared_kdf).__name__, **shared_args},
                    'chunker': {'name': type(chunker).__name__, **chunker_args},
                    'shared_encryption_secret': shared_kdf.derivation_params(),
                    'chunker_personalization': chunker.chunking_params()
                }
            }

        return config

    def _prepare_config(self, config, *, password=None, key=None):
        properties = utils.DefaultNamespace()
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
                # The key is still encrypted
                decrypted_private = properties.decrypt(
                    key['encrypted'], properties.userkey
                )
                private = self.deserialize(decrypted_private)

            properties.shared_kdf, _ = utils.adapter_from_config(**private['shared_kdf'])
            properties.derive_shared_key = functools.partial(
                properties.shared_kdf.derive, params=private['shared_encryption_secret']
            )

            # Chunking
            properties.chunker, _ = utils.adapter_from_config(**private['chunker'])
            properties.next_chunks = functools.partial(
                properties.chunker.next_chunks, params=private['chunker_personalization']
            )

        return properties

    async def unlock(self, *, password=None, key=None):
        data = await self.as_coroutine(self.backend.download, 'config')
        config = self.deserialize(data)

        # TODO: Load the key from the backend as a fallback?
        if isinstance(key, collections.abc.ByteString):
            key = self.deserialize(key)

        self.properties = self._prepare_config(config, password=password, key=key)

    async def init(self, *, password=None, settings=None):
        if settings is None:
            settings = {}

        config = self._make_config(utils.flat_to_nested(settings))
        key = config.pop('key', None)
        self.properties = self._prepare_config(config, password=password, key=key)

        if self.properties.encrypted:
            logger.debug(
                'New key (unencrypted):\n%s',
                json.dumps(key, indent=4, default=utils.type_hint)
            )
            key['encrypted'] = self.properties.encrypt(
                self.serialize(key.pop('private')), self.properties.userkey
            )
            print(
                'New key (encrypted):',
                json.dumps(key, indent=4, default=utils.type_hint)
            )

        logger.info('New config:\n%s',
            json.dumps(config, indent=4, sort_keys=True, default=utils.type_hint))

        await self.as_coroutine(self.backend.upload, 'config', self.serialize(config))
        return utils.DefaultNamespace(config=config, key=key)

    async def snapshot(self, *, paths):
        files = list(utils.fs.flatten_paths(paths))
        source_chunks = utils.fs.stream_files(files)
        for chunk in self.properties.next_chunks(source_chunks):
            print(chunk, len(chunk))
