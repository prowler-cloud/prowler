from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from colorama import Style

from prowler.config.config import orange_color
from prowler.lib.check.models import CheckReportM365
from prowler.lib.fix.fixer import Fixer, FixerMetadata
from prowler.lib.logger import logger


class M365Fixer(Fixer, ABC):
    """M365 specific fixer implementation"""

    def __init__(
        self, credentials: Optional[Dict] = None, session_config: Optional[Dict] = None
    ):
        """
        Initialize M365 fixer with optional credentials and session configuration.

        Args:
            credentials (Optional[Dict]): Optional M365 credentials for authentication
            session_config (Optional[Dict]): Optional M365 session configuration
        """
        super().__init__(credentials, session_config)
        self.service: str = ""
        self.client: Any = None

    @abstractmethod
    def _get_metadata(self) -> FixerMetadata:
        """Each fixer must define its metadata"""

    def fix(self, finding: Optional[CheckReportM365] = None, **kwargs) -> bool:
        """
        M365 specific method to execute the fixer.
        This method handles the printing of fixing status messages.

        Args:
            finding (Optional[CheckReportM365]): Finding to fix
            **kwargs: Additional M365-specific arguments (resource_id)

        Returns:
            bool: True if fixing was successful, False otherwise
        """
        try:
            # Get values either from finding or kwargs
            resource_id = None

            if finding:
                resource_id = (
                    finding.resource_id if hasattr(finding, "resource_id") else None
                )
            else:
                resource_id = kwargs.get("resource_id")

            # Print the appropriate message based on available information
            if resource_id:
                print(
                    f"\t{orange_color}FIXING Resource {resource_id}...{Style.RESET_ALL}"
                )
            else:
                logger.error(
                    "Either finding or required kwargs (resource_id) must be provided"
                )
                return False

            return True

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
