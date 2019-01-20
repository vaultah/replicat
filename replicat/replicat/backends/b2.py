import logging
from .. import Backend


logger = logging.getLogger(__name__)


class B2(Backend):

    def __init__(self, connection_string, *, account_id, application_key):
        pass

    async def upload(self, name, contents):
        pass

    async def download(self, name):
        pass

    async def list_files(self, prefix=''):
        pass

    async def hide_file(self, name):
        pass


Client = B2
