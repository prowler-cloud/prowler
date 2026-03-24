"""ASPM Credentials service."""

from prowler.providers.aspm.aspm_provider import AspmProvider
from prowler.providers.aspm.lib.service.service import AspmService


class Credentials(AspmService):
    """Service for AI agent credential management assessment.

    Inherits the agent list from AspmService and is used by all ASPM credentials
    checks (ASPM-026 through ASPM-036).
    """

    def __init__(self, provider: AspmProvider) -> None:
        """Initialise the Credentials service.

        Args:
            provider: The active AspmProvider instance.
        """
        super().__init__(provider)
