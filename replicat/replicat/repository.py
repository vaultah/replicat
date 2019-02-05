import asyncio
import base64
import functools
import inspect
import json
import logging
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from . import utils
from . import exceptions
from .utils import adapters

logger = logging.getLogger(__name__)


class Repository:

    def __init__(self, backend, *, concurrent, progress=False):
        self._slots = asyncio.Queue(maxsize=concurrent)
        # We need actual integers for TQDM slot management
        for x in range(concurrent):
            self._slots.put_nowait(x)
        self._progress = progress
        self.backend = backend

    def apply_defaults(self, config):
        encryption = config.setdefault('encryption', {})
        if encryption is not None:
            cipher_name = encryption.setdefault('cipher', 'aes_gcm')
            cipher_class = getattr(adapters, cipher_name)
            cipher = cipher_class(**encryption.get(cipher_name, {}))
            encryption[cipher_name] = dict(cipher)

            kdf_name = encryption.setdefault('kdf', 'scrypt')
            kdf_class = getattr(adapters, kdf_name)
            encryption[kdf_name] = dict(kdf_class(**encryption.get(kdf_name, {}),
                            length=cipher.key_bytes))

    def prepare_config(self, config):
        properties = utils.DefaultNamespace()
        encryption = config.get('encryption', None)

        if encryption is not None:
            cipher_name, kdf_name = encryption['cipher'], encryption['kdf']

            cipher_class = getattr(adapters, cipher_name)
            properties.cipher = cipher_class(**encryption[cipher_name])
            properties.encrypt = properties.cipher.encrypt
            properties.decrypt = properties.cipher.decrypt

            kdf_class = getattr(adapters, kdf_name)
            properties.kdf = kdf_class(**encryption[kdf_name])
            properties.derive_key = properties.kdf.derive
            # TODO: use enum?
            properties.encryption = 'symmetric'
        else:
            properties.encryption = None

        return properties

    def as_coroutine(self, func, *args, **kwargs):
        if inspect.iscoroutinefunction(func):
            return func(*args, **kwargs)
        else:
            loop = asyncio.get_event_loop()
            return loop.run_in_executor(self.executor, func, *args, **kwargs)

    def serialize(self, object):
        string = json.dumps(object, separators=(',', ':'), default=utils.type_hint)
        return bytes(string, 'ascii')

    def deserialize(self, data):
        return json.loads(data, object_hook=utils.type_reverse)

    @property
    def executor(self):
        """ Executor for non-async methods of `backend` """
        try:
            return self._executor
        except AttributeError:
            self._executor = ThreadPoolExecutor(max_workers=self._slots.maxsize)
            return self._executor

    async def unlock(self, *, password=None, key=None):
        data = await self.as_coroutine(self.backend.download, 'config')
        config = self.deserialize(data)
        encryption = config.get('encryption')

        if encryption is not None:
            # TODO: Load the key from the backend as a fallback?
            if password is None or key is None:
                raise exceptions.ReplicatError(
                        'Password and key are needed to unlock this repository')
            key = self.deserialize(key)
            encryption.update(key)
            repo = self.prepare_config(config)
            repo.userkey = repo.derive_key(password)
            decrypted = self.deserialize(repo.decrypt(key['encrypted'], repo.userkey))
            repo.shared_secret = decrypted['secret']

        self.properties = repo

    async def init(self, *, password=None, settings=None):
        if settings is None:
            settings = {}
        new = utils.flat_to_nested(settings)
        self.apply_defaults(new)
        repo = self.prepare_config(new)

        if repo.encryption is not None:
            if password is None:
                raise exceptions.ReplicatError('Password is needed')
            # Create the private/encrypted part of the key
            private = {'secret': os.urandom(64)}
            # Now yank the key portion out of the config
            encryption = new['encryption']
            kdf = encryption.pop('kdf')
            key = {'kdf': kdf, kdf: encryption.pop(kdf),
                   'encrypted': repo.encrypt(self.serialize(private),
                        repo.derive_key(password))}

            logger.info('New key: %s', json.dumps(key, indent=4,
                            sort_keys=True, default=utils.type_hint))

        logger.info('New config: %s', json.dumps(new, indent=4,
                        sort_keys=True, default=utils.type_hint))

        await self.as_coroutine(self.backend.upload, 'config', self.serialize(new))
