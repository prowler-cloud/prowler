"""ASPM Compliance service."""

from prowler.providers.aspm.aspm_provider import AspmProvider
from prowler.providers.aspm.lib.service.service import AspmService


class Compliance(AspmService):
    """Service for AI agent compliance and governance assessment.

    Inherits the agent list from AspmService and is used by all ASPM compliance
    checks (ASPM-087 through ASPM-095).
    """

    def __init__(self, provider: AspmProvider) -> None:
        """Initialise the Compliance service.

        Args:
            provider: The active AspmProvider instance.
        """
        super().__init__(provider)
