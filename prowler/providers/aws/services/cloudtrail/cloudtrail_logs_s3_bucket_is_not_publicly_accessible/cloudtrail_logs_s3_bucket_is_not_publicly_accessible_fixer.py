from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.s3.s3_client import s3_client


class CloudtrailLogsS3BucketIsNotPubliclyAccessibleFixer(AWSFixer):
    """
    Fixer for ensuring CloudTrail's associated S3 bucket is not publicly accessible.
    """

    def __init__(self):
        super().__init__(
            description="Modify the CloudTrail's associated S3 bucket's public access settings to ensure the bucket is not publicly accessible.",
            cost_impact=False,
            cost_description=None,
            service="cloudtrail",
            iam_policy_required={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:PutBucketPublicAccessBlock",
                        "Resource": "*",
                    }
                ],
            },
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Modify the CloudTrail's associated S3 bucket's public access settings to ensure the bucket is not publicly accessible.
        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix
            **kwargs: region, resource_id (if finding is not provided)
        Returns:
            bool: True if the operation is successful, False otherwise.
        """
        try:
            if finding:
                region = finding.region
                resource_id = finding.resource_id
            else:
                region = kwargs.get("region")
                resource_id = kwargs.get("resource_id")

            if not region or not resource_id:
                raise ValueError("Region and resource_id are required")

            super().fix(region=region, resource_id=resource_id)

            regional_client = s3_client.regional_clients[region]
            for trail in cloudtrail_client.trails.values():
                if trail.name == resource_id:
                    trail_bucket = trail.s3_bucket
                    regional_client.put_public_access_block(
                        Bucket=trail_bucket,
                        PublicAccessBlockConfiguration={
                            "BlockPublicAcls": True,
                            "IgnorePublicAcls": True,
                            "BlockPublicPolicy": True,
                            "RestrictPublicBuckets": True,
                        },
                    )
            return True
        except Exception as error:
            logger.error(
                f"{region if 'region' in locals() else 'unknown'} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
