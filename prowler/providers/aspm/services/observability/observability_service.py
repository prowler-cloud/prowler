"""ASPM Observability service."""

from prowler.providers.aspm.aspm_provider import AspmProvider
from prowler.providers.aspm.lib.service.service import AspmService


class Observability(AspmService):
    """Service for AI agent observability and monitoring assessment.

    Inherits the agent list from AspmService and is used by all ASPM
    observability checks (ASPM-077 through ASPM-086).
    """

    def __init__(self, provider: AspmProvider) -> None:
        """Initialise the Observability service.

        Args:
            provider: The active AspmProvider instance.
        """
        super().__init__(provider)
