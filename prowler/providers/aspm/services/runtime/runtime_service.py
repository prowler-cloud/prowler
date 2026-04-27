"""ASPM Runtime service."""

from prowler.providers.aspm.aspm_provider import AspmProvider
from prowler.providers.aspm.lib.service.service import AspmService


class Runtime(AspmService):
    """Service for AI agent runtime and sandbox security assessment.

    Inherits the agent list from AspmService and is used by all ASPM runtime
    checks (ASPM-058 through ASPM-067).
    """

    def __init__(self, provider: AspmProvider) -> None:
        """Initialise the Runtime service.

        Args:
            provider: The active AspmProvider instance.
        """
        super().__init__(provider)
