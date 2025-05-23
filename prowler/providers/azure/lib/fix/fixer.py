from typing import Optional

from colorama import Style

from prowler.config.config import orange_color
from prowler.lib.check.models import Check_Report_Azure
from prowler.lib.fix.fixer import Fixer
from prowler.lib.logger import logger


class AzureFixer(Fixer):
    """Azure specific fixer implementation"""

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

    def fix(self, finding: Optional[Check_Report_Azure] = None, **kwargs) -> bool:
        """
        Azure specific method to execute the fixer.
        This method handles the printing of fixing status messages.

        Args:
            finding (Optional[Check_Report_Azure]): Finding to fix
            **kwargs: Additional Azure-specific arguments (subscription_id, resource_id, resource_group)

        Returns:
            bool: True if fixing was successful, False otherwise
        """
        try:
            # Get values either from finding or kwargs
            subscription_id = None
            resource_id = None
            resource_group = None

            if finding:
                subscription_id = (
                    finding.subscription if hasattr(finding, "subscription") else None
                )
                resource_id = (
                    finding.resource_id if hasattr(finding, "resource_id") else None
                )
                resource_group = (
                    finding.resource_group_name
                    if hasattr(finding, "resource_group_name")
                    else None
                )
            else:
                subscription_id = kwargs.get("subscription_id")
                resource_id = kwargs.get("resource_id")
                resource_group = kwargs.get("resource_group")

            # Print the appropriate message based on available information
            if subscription_id and resource_id and resource_group:
                print(
                    f"\t{orange_color}FIXING Resource {resource_id} in Resource Group {resource_group} (Subscription: {subscription_id})...{Style.RESET_ALL}"
                )
            elif subscription_id and resource_id:
                print(
                    f"\t{orange_color}FIXING Resource {resource_id} (Subscription: {subscription_id})...{Style.RESET_ALL}"
                )
            elif subscription_id:
                print(
                    f"\t{orange_color}FIXING Subscription {subscription_id}...{Style.RESET_ALL}"
                )
            elif resource_id:
                print(
                    f"\t{orange_color}FIXING Resource {resource_id}...{Style.RESET_ALL}"
                )
            else:
                logger.error(
                    "Either finding or required kwargs (subscription_id, resource_id, resource_group) must be provided"
                )
                return False

            return True

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
