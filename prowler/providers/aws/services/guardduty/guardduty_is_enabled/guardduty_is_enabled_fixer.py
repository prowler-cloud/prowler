from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.guardduty.guardduty_client import guardduty_client


class GuarddutyIsEnabledFixer(AWSFixer):
    """
    Fixer to enable GuardDuty in a region.
    """

    def __init__(self):
        super().__init__(
            description="Enable GuardDuty in a region.",
            cost_impact=True,
            cost_description="Enabling GuardDuty incurs costs based on the volume of logs and events analyzed. Charges apply per GB of data processed and for threat detection features. See AWS GuardDuty pricing.",
            service="guardduty",
            iam_policy_required={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "guardduty:CreateDetector",
                        "Resource": "*",
                    }
                ],
            },
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Enable GuardDuty in a region.
        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix
            **kwargs: region (if finding is not provided)
        Returns:
            bool: True if GuardDuty is enabled, False otherwise
        """
        try:
            if finding:
                region = finding.region
            else:
                region = kwargs.get("region")

            if not region:
                raise ValueError("region is required")

            super().fix(region=region)

            regional_client = guardduty_client.regional_clients[region]
            regional_client.create_detector(Enable=True)
        except Exception as error:
            logger.error(
                f"{region if 'region' in locals() else 'unknown'} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
        else:
            return True
