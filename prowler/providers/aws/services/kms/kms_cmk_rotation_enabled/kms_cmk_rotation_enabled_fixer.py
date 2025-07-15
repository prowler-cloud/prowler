from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.kms.kms_client import kms_client


class KmsCmkRotationEnabledFixer(AWSFixer):
    """
    Fixer to enable CMK rotation.
    """

    def __init__(self):
        super().__init__(
            description="Enable CMK rotation.",
            cost_impact=False,
            cost_description=None,
            service="kms",
            iam_policy_required={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "kms:EnableKeyRotation",
                        "Resource": "*",
                    }
                ],
            },
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Enable CMK rotation.
        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix
            **kwargs: region, resource_id (if finding is not provided)
        Returns:
            bool: True if CMK rotation is enabled, False otherwise
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

            regional_client = kms_client.regional_clients[region]
            regional_client.enable_key_rotation(KeyId=resource_id)
        except Exception as error:
            logger.error(
                f"{region if 'region' in locals() else 'unknown'} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
        else:
            return True
