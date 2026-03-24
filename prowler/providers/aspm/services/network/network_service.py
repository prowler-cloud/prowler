"""ASPM Network service."""

from prowler.providers.aspm.aspm_provider import AspmProvider
from prowler.providers.aspm.lib.service.service import AspmService


class Network(AspmService):
    """Service for AI agent network security assessment.

    Inherits the agent list from AspmService and is used by all ASPM network
    checks (ASPM-037 through ASPM-046).
    """

    def __init__(self, provider: AspmProvider) -> None:
        """Initialise the Network service.

        Args:
            provider: The active AspmProvider instance.
        """
        super().__init__(provider)
