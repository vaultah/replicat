import abc
import logging

logger = logging.getLogger(__name__)


class Backend(abc.ABC):

    """All of the methods can be either async or plain functions. Backend adapters
    are responsible for implementing their own fault handling and retry strategies"""

    def __init__(self, connection_string, **ka):
        pass

    @abc.abstractmethod
    async def exists(self, name) -> bool:
        """Check whether a file with this name exists at the backend"""
        return True

    @abc.abstractmethod
    async def upload(self, name, data):
        """Upload bytes-like data to the backend under this name"""
        return None

    @abc.abstractmethod
    async def upload_stream(self, name, stream, length):
        """Upload seekable file-like stream to the backend under this name"""
        return None

    @abc.abstractmethod
    async def download(self, name) -> bytes:
        """Download file from the backend by name and return its contents as bytes"""
        return b''

    @abc.abstractmethod
    async def download_stream(self, name, stream):
        return None

    @abc.abstractmethod
    async def list_files(self, prefix=''):
        """Get the list of files from the backend. Restricts the results to
        non-deleted files starting with this prefix. The return value can be a
        plain iterable or an async iterator"""
        return None

    @abc.abstractmethod
    async def delete(self, name):
        """Delete file by name"""
        return None

    async def authenticate(self):
        """Called to authenticate the client (see the @requires_auth decorator).
        Must have the same type as the function that requires authentication"""
        raise NotImplementedError

    async def clean(self):
        """Perform clean up at the backend"""
        pass

    async def close(self):
        """Close instance resources"""
        pass

    def __init_subclass__(cls, /, short_name=None, display_name=None, **kwargs):
        super().__init_subclass__(**kwargs)

        if short_name is None:
            short_name = cls.__name__

        if display_name is None:
            display_name = short_name

        cls.short_name = short_name
        cls.display_name = display_name
