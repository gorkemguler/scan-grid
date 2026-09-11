"""CVE matching subsystem.

``get_provider()`` returns the configured backend:

* ``nvd_api``  - live queries to the NVD 2.0 REST API (rate-limited, DB-cached)
* ``offline``  - matches against NVD JSON feeds on local disk
* ``none``     - disabled (no findings)
"""

from __future__ import annotations

from functools import lru_cache

from ..config import get_settings
from .base import CveProvider, NullProvider, Vulnerability

__all__ = ["CveProvider", "NullProvider", "Vulnerability", "get_provider"]


@lru_cache(maxsize=1)
def get_provider() -> CveProvider:
    name = get_settings().cve_provider
    if name == "nvd_api":
        from .nvd_api import NvdApiProvider

        return NvdApiProvider()
    if name == "offline":
        from .offline import OfflineNvdProvider

        return OfflineNvdProvider()
    return NullProvider()


def reset_provider_cache() -> None:
    get_provider.cache_clear()
