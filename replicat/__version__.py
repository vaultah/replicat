import sys
from typing import List, Tuple

version_info = (1, 6, 0)
version = '.'.join(map(str, version_info))


class _VersionInfo(str):
    version: str
    version_info: Tuple[int, ...]
    __all__: List[str]


_version_module = _VersionInfo(version)
_version_module.version = version
_version_module.version_info = version_info
_version_module.__all__ = ['version', 'version_info']
sys.modules[__name__] = _version_module  # type: ignore[assignment]
