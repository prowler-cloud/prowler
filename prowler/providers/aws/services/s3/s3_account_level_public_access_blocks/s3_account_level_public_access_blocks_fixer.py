from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.s3.s3control_client import s3control_client


class S3AccountLevelPublicAccessBlocksFixer(AWSFixer):
    """
    Fixer to enable S3 Block Public Access for the account.
    """

    def __init__(self):
        super().__init__(
            description="Enable S3 Block Public Access for the account.",
            cost_impact=False,
            cost_description=None,
            service="s3",
            iam_policy_required={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:PutAccountPublicAccessBlock",
                        "Resource": "*",
                    }
                ],
            },
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Enable S3 Block Public Access for the account.
        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix
            **kwargs: resource_id (account id, if finding is not provided)
        Returns:
            bool: True if S3 Block Public Access is enabled, False otherwise
        """
        try:
            if finding:
                resource_id = finding.resource_id
            else:
                resource_id = kwargs.get("resource_id")

            if not resource_id:
                raise ValueError("resource_id (account id) is required")

            super().fix()

            s3control_client.client.put_public_access_block(
                AccountId=resource_id,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
        else:
            return True
