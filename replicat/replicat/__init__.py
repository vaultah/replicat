import abc
import logging

logger = logging.getLogger(__name__)


class Backend(abc.ABC):
    def __init__(self, connection_string, **ka):
        pass

    @abc.abstractmethod
    async def upload(self, name, contents, **ka):
        """ Either async or plain function """
        return None

    @abc.abstractmethod
    async def download(self, name, **ka):
        """ Either async or plain function """
        return None

    @abc.abstractmethod
    async def list_files(self, prefix='', **ka):
        """ Either async or plain function """
        return None

    @abc.abstractmethod
    async def hide_file(self, name):
        """ Either async or plain function """
        return None

    async def authenticate(self):
        """ Either async or plain function. Also, it's optional, and must
            have the same type as the methods that need authentication """
        raise NotImplementedError
