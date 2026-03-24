"""ASPM Attack Paths service."""

from prowler.providers.aspm.aspm_provider import AspmProvider
from prowler.providers.aspm.lib.service.service import AspmService


class AttackPaths(AspmService):
    """Service for AI agent attack path analysis.

    Inherits the agent list from AspmService and is used by all ASPM attack
    path checks (ASPM-096 through ASPM-101).
    """

    def __init__(self, provider: AspmProvider) -> None:
        """Initialise the AttackPaths service.

        Args:
            provider: The active AspmProvider instance.
        """
        super().__init__(provider)
