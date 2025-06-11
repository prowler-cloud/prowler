from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)


class CloudtrailMultiRegionEnabledFixer(AWSFixer):
    """
    Fixer for enabling CloudTrail as a multi-region trail in a region.
    """

    def __init__(self):
        super().__init__(
            description="Enable CloudTrail as a multi-region trail in a region.",
            cost_impact=False,
            cost_description=None,
            service="cloudtrail",
            iam_policy_required={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "cloudtrail:CreateTrail",
                        "Resource": "*",
                    }
                ],
            },
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Enable CloudTrail as a multi-region trail in a region.
        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix
            **kwargs: region (if finding is not provided)
        Returns:
            bool: True if CloudTrail is enabled, False otherwise
        """
        try:
            if finding:
                region = finding.region
            else:
                region = kwargs.get("region")

            if not region:
                raise ValueError("Region is required")

            super().fix(region=region)

            cloudtrail_fixer_config = cloudtrail_client.fixer_config.get(
                "cloudtrail_multi_region_enabled", {}
            )
            regional_client = cloudtrail_client.regional_clients[region]
            args = {
                "Name": cloudtrail_fixer_config.get("TrailName", "DefaultTrail"),
                "S3BucketName": cloudtrail_fixer_config.get("S3BucketName"),
                "IsMultiRegionTrail": cloudtrail_fixer_config.get(
                    "IsMultiRegionTrail", True
                ),
                "EnableLogFileValidation": cloudtrail_fixer_config.get(
                    "EnableLogFileValidation", True
                ),
            }
            if cloudtrail_fixer_config.get("CloudWatchLogsLogGroupArn"):
                args["CloudWatchLogsLogGroupArn"] = cloudtrail_fixer_config.get(
                    "CloudWatchLogsLogGroupArn"
                )
            if cloudtrail_fixer_config.get("CloudWatchLogsRoleArn"):
                args["CloudWatchLogsRoleArn"] = cloudtrail_fixer_config.get(
                    "CloudWatchLogsRoleArn"
                )
            if cloudtrail_fixer_config.get("KmsKeyId"):
                args["KmsKeyId"] = cloudtrail_fixer_config.get("KmsKeyId")
            regional_client.create_trail(**args)
            return True
        except Exception as error:
            logger.error(
                f"{region if 'region' in locals() else 'unknown'} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
