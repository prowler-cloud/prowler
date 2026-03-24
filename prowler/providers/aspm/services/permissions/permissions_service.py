"""ASPM Permissions service."""

from prowler.providers.aspm.aspm_provider import AspmProvider
from prowler.providers.aspm.lib.service.service import AspmService


class Permissions(AspmService):
    """Service for AI agent permissions and least-privilege assessment.

    Inherits the agent list from AspmService and is used by all ASPM
    permissions checks (ASPM-013 through ASPM-025).
    """

    def __init__(self, provider: AspmProvider) -> None:
        """Initialise the Permissions service.

        Args:
            provider: The active AspmProvider instance.
        """
        super().__init__(provider)
