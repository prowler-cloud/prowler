"""ASPM Supply Chain service."""

from prowler.providers.aspm.aspm_provider import AspmProvider
from prowler.providers.aspm.lib.service.service import AspmService


class SupplyChain(AspmService):
    """Service for AI agent supply chain security assessment.

    Inherits the agent list from AspmService and is used by all ASPM supply chain
    checks (ASPM-068 through ASPM-076).
    """

    def __init__(self, provider: AspmProvider) -> None:
        """Initialise the SupplyChain service.

        Args:
            provider: The active AspmProvider instance.
        """
        super().__init__(provider)
