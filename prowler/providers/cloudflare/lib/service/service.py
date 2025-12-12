from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING

from prowler.lib.logger import logger

# TYPE_CHECKING imports to maintain Prowler's provider structure where models live in their modules.
# This breaks the following import cycles at runtime:
#   service.py -> cloudflare_provider.py -> zones_service.py -> service.py (for CloudflareProvider)
#   service.py -> zones_service.py -> service.py (for CloudflareZone)
# Safe because: (1) `from __future__ import annotations` (PEP 563) defers annotation evaluation,
# and (2) TYPE_CHECKING blocks only execute for type checkers, not at runtime.
if TYPE_CHECKING:
    from prowler.providers.cloudflare.cloudflare_provider import CloudflareProvider
    from prowler.providers.cloudflare.services.zones.zones_service import CloudflareZone

MAX_WORKERS = 10


class CloudflareService:
    """Base class for Cloudflare services to share provider context and threading helpers."""

    def __init__(self, service: str, provider: CloudflareProvider):
        self.provider = provider
        self.client = provider.session.client
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
        self.service = service.lower() if not service.islower() else service
        self.zones: list[CloudflareZone] = provider.zones
        self.thread_pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    def __threading_call__(self, call, iterator=None):
        items = iterator if iterator is not None else self.zones
        futures = [self.thread_pool.submit(call, item) for item in items]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
