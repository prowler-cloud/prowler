"""ASPM base service class."""

from prowler.lib.logger import logger
from prowler.providers.aspm.aspm_provider import AspmProvider


class AspmService:
    """Base class for all ASPM services.

    Each subclass is responsible for a specific check category (identity,
    permissions, credentials, …).  On construction the service receives the
    global AspmProvider instance and exposes the filtered list of agents that
    the checks iterate over.

    Attributes:
        provider: The active AspmProvider instance.
        agents: The list of AgentConfig objects to assess.
    """

    def __init__(self, provider: AspmProvider) -> None:
        """Initialise the service with a reference to the provider.

        Args:
            provider: The active AspmProvider instance.
        """
        logger.info(f"Initialising {self.__class__.__name__}...")
        self.provider = provider
        self.agents = provider.agents
