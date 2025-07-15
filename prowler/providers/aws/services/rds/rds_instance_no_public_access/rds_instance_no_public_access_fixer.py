from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.rds.rds_client import rds_client


class RdsInstanceNoPublicAccessFixer(AWSFixer):
    """
    Fixer to disable public accessibility for RDS instances.
    """

    def __init__(self):
        super().__init__(
            description="Disable public accessibility for RDS instances.",
            cost_impact=False,
            cost_description=None,
            service="rds",
            iam_policy_required={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "rds:ModifyDBInstance",
                        "Resource": "*",
                    }
                ],
            },
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Disable public accessibility for RDS instances.
        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix
            **kwargs: region, resource_id (if finding is not provided)
        Returns:
            bool: True if public access is disabled, False otherwise.
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

            regional_client = rds_client.regional_clients[region]
            regional_client.modify_db_instance(
                DBInstanceIdentifier=resource_id,
                PubliclyAccessible=False,
                ApplyImmediately=True,
            )
        except Exception as error:
            logger.error(
                f"{region if 'region' in locals() else 'unknown'} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
        else:
            return True
