import abc
import logging

logger = logging.getLogger(__name__)


class Backend(abc.ABC):
    def __init__(self, connection_string, **ka):
        pass

    @abc.abstractmethod
    async def exists(self, name) -> bool:
        """Either async or plain function"""
        return True

    @abc.abstractmethod
    async def upload(self, name, data, **ka):
        """Either async or plain function"""
        return None

    @abc.abstractmethod
    async def download(self, name, **ka) -> bytes:
        """Either async or plain function"""
        return b''

    @abc.abstractmethod
    async def list_files(self, prefix='', **ka):
        """Either async or plain function"""
        return None

    @abc.abstractmethod
    async def delete(self, name):
        """Either async or plain function"""
        return None

    async def authenticate(self):
        """Either async or plain function. Also, it's optional, and must
        have the same type as the methods that need authentication"""
        raise NotImplementedError

    async def close(self):
        """Either async or plain function"""
        pass

    async def clean(self):
        """Either async or plain function"""
        pass
