from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.documentdb.documentdb_client import (
    documentdb_client,
)


class DocumentdbClusterPublicSnapshotFixer(AWSFixer):
    """
    Fixer for modifying the attributes of a DocumentDB cluster snapshot to remove public access.
    """

    def __init__(self):
        super().__init__(
            description="Modify the attributes of a DocumentDB cluster snapshot to remove public access.",
            cost_impact=False,
            cost_description=None,
            service="documentdb",
            iam_policy_required={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "rds:ModifyDBClusterSnapshotAttribute",
                        "Resource": "*",
                    }
                ],
            },
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Modify the attributes of a DocumentDB cluster snapshot to remove public access.
        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix
            **kwargs: region, resource_id (if finding is not provided)
        Returns:
            bool: True if the operation is successful (public access is removed), False otherwise.
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

            regional_client = documentdb_client.regional_clients[region]
            regional_client.modify_db_cluster_snapshot_attribute(
                DBClusterSnapshotIdentifier=resource_id,
                AttributeName="restore",
                ValuesToRemove=["all"],
            )
            return True
        except Exception as error:
            logger.error(
                f"{region if 'region' in locals() else 'unknown'} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
