from typing import Dict, Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer, FixerMetadata
from prowler.providers.aws.services.kms.kms_client import kms_client


class KmsCmkNotDeletedUnintentionallyFixer(AWSFixer):
    """
    Fixer for KMS keys marked for deletion
    """

    def __init__(
        self, credentials: Optional[Dict] = None, session_config: Optional[Dict] = None
    ):
        super().__init__(credentials, session_config)
        self.service = "kms"
        self.iam_policy_required = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "kms:CancelKeyDeletion", "Resource": "*"}
            ],
        }

    def _get_metadata(self) -> FixerMetadata:
        return FixerMetadata(
            description="Cancel the scheduled deletion of a KMS key",
            cost_impact=False,
            cost_description=None,
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Cancel the scheduled deletion of a KMS key.
        Specifically, this fixer calls the 'cancel_key_deletion' method to restore the KMS key's availability if it is marked for deletion.

        Args:
            finding (Check_Report_AWS): Finding to fix
            **kwargs: Additional arguments (region and resource_id are required if finding is not provided)

        Returns:
            bool: True if the operation is successful (deletion cancellation is completed), False otherwise
        """
        try:
            # Get region and resource_id either from finding or kwargs
            if finding:
                region = finding.region
                resource_id = finding.resource_id
            else:
                region = kwargs.get("region")
                resource_id = kwargs.get("resource_id")

            if not region or not resource_id:
                raise ValueError("Region and resource_id are required")

            # Get the client for this region
            regional_client = kms_client.regional_clients[region]

            # Cancel key deletion
            regional_client.cancel_key_deletion(KeyId=resource_id)
            return True
        except Exception as error:
            logger.error(
                f"{region if 'region' in locals() else 'unknown'} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
