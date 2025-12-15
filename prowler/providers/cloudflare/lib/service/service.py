from __future__ import annotations

from typing import TYPE_CHECKING

# TYPE_CHECKING import to avoid circular dependency at runtime:
#   service.py -> cloudflare_provider.py -> service.py (for CloudflareProvider)
# Safe because `from __future__ import annotations` (PEP 563) defers annotation evaluation.
if TYPE_CHECKING:
    from prowler.providers.cloudflare.cloudflare_provider import CloudflareProvider


class CloudflareService:
    """Base class for Cloudflare services to share provider context."""

    def __init__(self, service: str, provider: CloudflareProvider):
        self.provider = provider
        self.client = provider.session.client
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
        self.service = service.lower() if not service.islower() else service
