from prowler.providers.e2enetworks.e2enetworks_provider import E2enetworksProvider
from prowler.providers.e2enetworks.lib.api.client import E2eNetworksAPIClient


class E2eNetworksService:
    """Base class for E2E Networks services."""

    def __init__(self, service: str, provider: E2enetworksProvider):
        """Initialize an E2E Networks service client.

        Args:
            service: Service name used for logging and configuration lookup.
            provider: The active E2E Networks provider instance.
        """
        self.provider = provider
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
        self.service = service.lower() if not service.islower() else service
        self.client = E2eNetworksAPIClient(provider.session)
