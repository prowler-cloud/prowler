from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from colorama import Style

from prowler.config.config import orange_color
from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.fix.fixer import Fixer, FixerMetadata
from prowler.lib.logger import logger


class AWSFixer(Fixer, ABC):
    """AWS specific fixer implementation"""

    def __init__(
        self, credentials: Optional[Dict] = None, session_config: Optional[Dict] = None
    ):
        super().__init__(credentials, session_config)
        self.service: str = ""
        self.regional_clients: Dict[str, Any] = {}
        self.iam_policy_required: Dict = {}

    @abstractmethod
    def _get_metadata(self) -> FixerMetadata:
        """Each fixer must define its metadata"""

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        AWS specific method to execute the fixer.
        This method handles the printing of fixing status messages.

        Args:
            finding (Check_Report_AWS): Finding to fix
            **kwargs: Additional AWS-specific arguments

        Returns:
            bool: True if fixing was successful, False otherwise
        """
        try:
            if not finding:
                logger.error("Finding is required")
                return False

            # Print the appropriate message based on available information
            if hasattr(finding, "region") and hasattr(finding, "resource_id"):
                print(
                    f"\t{orange_color}FIXING {finding.resource_id} in {finding.region}...{Style.RESET_ALL}"
                )
            elif hasattr(finding, "region"):
                print(f"\t{orange_color}FIXING {finding.region}...{Style.RESET_ALL}")
            elif hasattr(finding, "resource_arn"):
                print(
                    f"\t{orange_color}FIXING Resource {finding.resource_arn}...{Style.RESET_ALL}"
                )
            elif hasattr(finding, "resource_id"):
                print(
                    f"\t{orange_color}FIXING Resource {finding.resource_id}...{Style.RESET_ALL}"
                )

            return True

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
