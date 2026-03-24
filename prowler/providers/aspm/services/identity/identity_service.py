"""ASPM Identity service."""

from prowler.providers.aspm.aspm_provider import AspmProvider
from prowler.providers.aspm.lib.service.service import AspmService


class Identity(AspmService):
    """Service for AI agent identity and authentication assessment.

    Inherits the agent list from AspmService and is used by all ASPM identity
    checks (ASPM-001 through ASPM-012).
    """

    def __init__(self, provider: AspmProvider) -> None:
        """Initialise the Identity service.

        Args:
            provider: The active AspmProvider instance.
        """
        super().__init__(provider)
