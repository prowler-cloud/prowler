from prowler.providers.e2e.lib.api.client import E2eAPIClient


class E2eService:
    """Base class for E2E Cloud services."""

    def __init__(self, service: str, provider):
        self.provider = provider
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
        self.service = service.lower() if not service.islower() else service
        self.client = E2eAPIClient(provider.session)
