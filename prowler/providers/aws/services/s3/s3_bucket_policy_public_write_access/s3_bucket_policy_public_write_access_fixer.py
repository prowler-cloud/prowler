from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.s3.s3_client import s3_client


class S3BucketPolicyPublicWriteAccessFixer(AWSFixer):
    """
    Fixer to remove public write access from S3 bucket policies.
    """

    def __init__(self):
        super().__init__(
            description="Remove public write access from S3 bucket policies.",
            cost_impact=False,
            cost_description=None,
            service="s3",
            iam_policy_required={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:DeleteBucketPolicy",
                        "Resource": "*",
                    }
                ],
            },
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Remove public write access from S3 bucket policies.
        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix
            **kwargs: region, resource_id (if finding is not provided)
        Returns:
            bool: True if the policy is removed, False otherwise.
        """
        try:
            if finding:
                region = finding.region
                resource_id = finding.resource_id
            else:
                region = kwargs.get("region")
                resource_id = kwargs.get("resource_id")

            if not region or not resource_id:
                raise ValueError("region and resource_id are required")

            super().fix(region=region, resource_id=resource_id)

            regional_client = s3_client.regional_clients[region]
            regional_client.delete_bucket_policy(Bucket=resource_id)
        except Exception as error:
            logger.error(
                f"{region if 'region' in locals() else 'unknown'} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
        else:
            return True
