"""IONOS Base Service Module for Prowler."""

from prowler.providers.ionos.ionos_provider import IonosProvider


class IonosService:
    """Base class for all IONOS services."""

    def __init__(self, provider: IonosProvider):
        """Initialize the IonosService class."""
        self.provider = provider
        self.session = self.provider.session
        self.identity = self.provider.identity
        self.audited_partition = "ionos"
