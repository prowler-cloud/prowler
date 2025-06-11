from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class Ec2EbsDefaultEncryptionFixer(AWSFixer):
    """
    Fixer to enable EBS encryption by default in a region.
    """

    def __init__(self):
        super().__init__(
            description="Enable EBS encryption by default in a region. NOTE: Custom KMS keys for EBS Default Encryption may be overwritten.",
            cost_impact=False,
            cost_description=None,
            service="ec2",
            iam_policy_required={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "ec2:EnableEbsEncryptionByDefault",
                        "Resource": "*",
                    }
                ],
            },
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Enable EBS encryption by default in a region.
        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix
            **kwargs: region (if finding is not provided)
        Returns:
            bool: True if EBS encryption by default is enabled, False otherwise
        """
        try:
            if finding:
                region = finding.region
            else:
                region = kwargs.get("region")

            if not region:
                raise ValueError("Region is required")

            super().fix(region=region)

            regional_client = ec2_client.regional_clients[region]
            return regional_client.enable_ebs_encryption_by_default()[
                "EbsEncryptionByDefault"
            ]
        except Exception as error:
            logger.error(
                f"{region if 'region' in locals() else 'unknown'} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
