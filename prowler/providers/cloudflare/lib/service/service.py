from prowler.providers.cloudflare.cloudflare_provider import CloudflareProvider


class CloudflareService:
    """Base class for Cloudflare services to share provider context."""

    def __init__(self, service: str, provider: CloudflareProvider):
        self.provider = provider
        self.client = provider.session.client
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
        self.service = service.lower() if not service.islower() else service
