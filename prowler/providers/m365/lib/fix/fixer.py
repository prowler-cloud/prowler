from typing import Optional

from colorama import Style

from prowler.config.config import orange_color
from prowler.lib.check.models import CheckReportM365
from prowler.lib.fix.fixer import Fixer
from prowler.lib.logger import logger


class M365Fixer(Fixer):
    """M365 specific fixer implementation"""

    def __init__(
        self,
        description: str,
        cost_impact: bool = False,
        cost_description: Optional[str] = None,
        service: str = "",
    ):
        super().__init__(description, cost_impact, cost_description)
        self.service = service

    def _get_fixer_info(self):
        """Each fixer must define its metadata"""
        fixer_info = super()._get_fixer_info()
        fixer_info["service"] = self.service
        return fixer_info

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
            elif kwargs.get("resource_id"):
                resource_id = kwargs.get("resource_id")

            # Print the appropriate message based on available information
            if resource_id:
                print(
                    f"\t{orange_color}FIXING Resource {resource_id}...{Style.RESET_ALL}"
                )
            else:
                # If no resource_id is provided, we'll still try to proceed
                print(f"\t{orange_color}FIXING...{Style.RESET_ALL}")

            return True

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
