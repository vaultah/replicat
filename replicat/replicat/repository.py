import asyncio
import inspect
import logging
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


class Repository:

    def __init__(self, backend, *, concurrent, progress=False):
        self._slots = asyncio.Queue(maxsize=concurrent)
        # We need actual integers for TQDM slot management
        for x in range(concurrent):
            self._slots.put_nowait(x)
        self._progress = progress
        self.backend = backend

    def _as_async(self, func, *args, **kwargs):
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

    async def unlock(self, *, password=None, keyfile=None):
        # If the keyfile is not given, we assume it's stored in the repo
        pass
