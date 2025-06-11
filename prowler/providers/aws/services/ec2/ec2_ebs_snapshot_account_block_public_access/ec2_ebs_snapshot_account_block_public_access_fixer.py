from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class Ec2EbsSnapshotAccountBlockPublicAccessFixer(AWSFixer):
    """
    Fixer to enable EBS snapshot block public access in a region.
    """

    def __init__(self):
        super().__init__(
            description="Enable EBS snapshot block public access in a region.",
            cost_impact=False,
            cost_description=None,
            service="ec2",
            iam_policy_required={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "ec2:EnableSnapshotBlockPublicAccess",
                        "Resource": "*",
                    }
                ],
            },
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Enable EBS snapshot block public access in a region.
        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix
            **kwargs: region (if finding is not provided)
        Returns:
            bool: True if EBS snapshot block public access is enabled, False otherwise
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
            state = ec2_client.fixer_config.get(
                "ec2_ebs_snapshot_account_block_public_access", {}
            ).get("State", "block-all-sharing")
            return (
                regional_client.enable_snapshot_block_public_access(State=state)[
                    "State"
                ]
                == state
            )
        except Exception as error:
            logger.error(
                f"{region if 'region' in locals() else 'unknown'} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
