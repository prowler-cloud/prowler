from typing import Dict, Optional

from colorama import Style

from prowler.config.config import orange_color
from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.fix.fixer import Fixer
from prowler.lib.logger import logger


class AWSFixer(Fixer):
    """AWS specific fixer implementation"""

    def __init__(
        self,
        description: str,
        cost_impact: bool = False,
        cost_description: Optional[str] = None,
        service: str = "",
        iam_policy_required: Optional[Dict] = None,
    ):
        """
        Initialize AWS fixer with metadata.

        Args:
            description (str): Description of the fixer
            cost_impact (bool): Whether the fixer has a cost impact
            cost_description (Optional[str]): Description of the cost impact
            service (str): AWS service name
            iam_policy_required (Optional[Dict]): Required IAM policy for the fixer
        """
        super().__init__(description, cost_impact, cost_description)
        self.service = service
        self.iam_policy_required = iam_policy_required or {}

    def _get_fixer_info(self):
        """Each fixer must define its metadata"""
        fixer_info = super()._get_fixer_info()
        fixer_info["service"] = self.service
        fixer_info["iam_policy_required"] = self.iam_policy_required
        return fixer_info

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        AWS specific method to execute the fixer.
        This method handles the printing of fixing status messages.

        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix
            **kwargs: Additional AWS-specific arguments (region, resource_id, resource_arn)

        Returns:
            bool: True if fixing was successful, False otherwise
        """
        try:
            # Get values either from finding or kwargs
            region = None
            resource_id = None
            resource_arn = None

            if finding:
                region = finding.region if hasattr(finding, "region") else None
                resource_id = (
                    finding.resource_id if hasattr(finding, "resource_id") else None
                )
                resource_arn = (
                    finding.resource_arn if hasattr(finding, "resource_arn") else None
                )
            else:
                region = kwargs.get("region")
                resource_id = kwargs.get("resource_id")
                resource_arn = kwargs.get("resource_arn")

            # Print the appropriate message based on available information
            if region and resource_id:
                print(
                    f"\t{orange_color}FIXING {resource_id} in {region}...{Style.RESET_ALL}"
                )
            elif region:
                print(f"\t{orange_color}FIXING {region}...{Style.RESET_ALL}")
            elif resource_arn:
                print(
                    f"\t{orange_color}FIXING Resource {resource_arn}...{Style.RESET_ALL}"
                )
            elif resource_id:
                print(
                    f"\t{orange_color}FIXING Resource {resource_id}...{Style.RESET_ALL}"
                )
            else:
                logger.error(
                    "Either finding or required kwargs (region, resource_id, resource_arn) must be provided"
                )
                return False

            return True

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
