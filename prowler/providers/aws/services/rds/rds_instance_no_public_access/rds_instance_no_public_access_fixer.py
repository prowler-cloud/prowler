from typing import Dict, Optional

from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer, FixerMetadata
from prowler.providers.aws.services.rds.rds_client import rds_client


class RdsInstanceNoPublicAccessFixer(AWSFixer):
    """
    Fixer for RDS instances with public access
    """

    def __init__(
        self, credentials: Optional[Dict] = None, session_config: Optional[Dict] = None
    ):
        super().__init__(credentials, session_config)
        self.service = "rds"
        self.iam_policy_required = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "rds:ModifyDBInstance", "Resource": "*"}
            ],
        }

    def _get_metadata(self) -> FixerMetadata:
        return FixerMetadata(
            description="Disable public accessibility for RDS instance",
            cost_impact=False,
            cost_description=None,
        )

    def fix(self, finding: Optional[Dict] = None, **kwargs) -> bool:
        """
        Modify the attributes of an RDS instance to disable public accessibility.
        Specifically, this fixer sets the 'PubliclyAccessible' attribute to False
        to prevent the RDS instance from being publicly accessible.

        Args:
            finding (Dict): Finding to fix
            **kwargs: Additional arguments (region and resource_id are required if finding is not provided)

        Returns:
            bool: True if the operation is successful (public access is disabled), False otherwise
        """
        try:
            # Get region and resource_id either from finding or kwargs
            if finding:
                region = finding.get("Region") or finding.get("region")
                resource_id = finding.get("ResourceId") or finding.get("resource_id")
            else:
                region = kwargs.get("region")
                resource_id = kwargs.get("resource_id")

            if not region or not resource_id:
                raise ValueError("Region and resource_id are required")

            # Get the client for this region
            regional_client = rds_client.regional_clients[region]

            # Modify the DB instance
            regional_client.modify_db_instance(
                DBInstanceIdentifier=resource_id,
                PubliclyAccessible=False,
                ApplyImmediately=True,
            )
            return True
        except Exception as error:
            logger.error(
                f"{region if 'region' in locals() else 'unknown'} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
