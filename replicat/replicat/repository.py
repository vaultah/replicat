import logging

logger = logging.getLogger(__name__)


class Repository:

    def __init__(self, backend):
        self.backend = backend
