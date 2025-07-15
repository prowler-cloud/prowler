from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.securityhub.securityhub_client import (
    securityhub_client,
)


class SecurityhubEnabledFixer(AWSFixer):
    """
    Fixer to enable Security Hub in a region.
    """

    def __init__(self):
        super().__init__(
            description="Enable Security Hub in a region.",
            cost_impact=True,
            cost_description="Enabling Security Hub incurs costs for findings ingestion, analysis, and resource coverage. Charges apply per finding and per resource. See AWS Security Hub pricing.",
            service="securityhub",
            iam_policy_required={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "securityhub:EnableSecurityHub",
                        "Resource": "*",
                    }
                ],
            },
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Enable Security Hub in a region.
        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix
            **kwargs: region (if finding is not provided)
        Returns:
            bool: True if Security Hub is enabled, False otherwise
        """
        try:
            if finding:
                region = finding.region
            else:
                region = kwargs.get("region")

            if not region:
                raise ValueError("region is required")

            super().fix(region=region)

            regional_client = securityhub_client.regional_clients[region]
            regional_client.enable_security_hub(
                EnableDefaultStandards=securityhub_client.fixer_config.get(
                    "securityhub_enabled", {}
                ).get("EnableDefaultStandards", True)
            )
        except Exception as error:
            logger.error(
                f"{region if 'region' in locals() else 'unknown'} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
        else:
            return True
