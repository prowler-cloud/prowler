from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.glacier.glacier_client import glacier_client


class GlacierVaultsPolicyPublicAccessFixer(AWSFixer):
    """
    Fixer to remove public access from Glacier vaults by deleting their access policy.
    """

    def __init__(self):
        super().__init__(
            description="Remove public access from Glacier vaults by deleting their access policy.",
            cost_impact=False,
            cost_description=None,
            service="glacier",
            iam_policy_required={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "glacier:DeleteVaultAccessPolicy",
                        "Resource": "*",
                    }
                ],
            },
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Remove public access from Glacier vaults by deleting their access policy.
        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix
            **kwargs: resource_id, region (if finding is not provided)
        Returns:
            bool: True if the operation is successful (policy updated), False otherwise.
        """
        try:
            if finding:
                resource_id = finding.resource_id
                region = finding.region
            else:
                resource_id = kwargs.get("resource_id")
                region = kwargs.get("region")

            if not resource_id or not region:
                raise ValueError("resource_id and region are required")

            super().fix(region=region)

            regional_client = glacier_client.regional_clients[region]
            regional_client.delete_vault_access_policy(vaultName=resource_id)
        except Exception as error:
            logger.error(
                f"{region if 'region' in locals() else 'unknown'} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
        else:
            return True
