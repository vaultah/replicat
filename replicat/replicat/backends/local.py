import logging
from .. import Backend


logger = logging.getLogger(__name__)


class Local(Backend):

    def __init__(self, connection_string):
        pass

    def upload(self, name, contents):
        pass

    def download(self, name):
        pass

    def list_files(self, prefix=''):
        pass

    def hide_file(self, name):
        pass


Client = Local
