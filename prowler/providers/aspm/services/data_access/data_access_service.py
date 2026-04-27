"""ASPM Data Access service."""

from prowler.providers.aspm.aspm_provider import AspmProvider
from prowler.providers.aspm.lib.service.service import AspmService


class DataAccess(AspmService):
    """Service for AI agent data access and privacy assessment.

    Inherits the agent list from AspmService and is used by all ASPM
    data access checks (ASPM-047 through ASPM-057).
    """

    def __init__(self, provider: AspmProvider) -> None:
        """Initialise the DataAccess service.

        Args:
            provider: The active AspmProvider instance.
        """
        super().__init__(provider)
