from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.rds.rds_client import rds_client


class RdsSnapshotsPublicAccessFixer(AWSFixer):
    """
    Fixer to remove public access from RDS DB snapshots and DB cluster snapshots.
    """

    def __init__(self):
        super().__init__(
            description="Remove public access from RDS DB snapshots and DB cluster snapshots.",
            cost_impact=False,
            cost_description=None,
            service="rds",
            iam_policy_required={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "rds:ModifyDBSnapshotAttribute",
                        "Resource": "*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": "rds:ModifyDBClusterSnapshotAttribute",
                        "Resource": "*",
                    },
                ],
            },
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Remove public access from RDS DB snapshots and DB cluster snapshots.
        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix
            **kwargs: region, resource_id (if finding is not provided)
        Returns:
            bool: True if public access is removed, False otherwise.
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

            # Check if the resource is a DB Cluster Snapshot or a DB Instance Snapshot
            try:
                regional_client.describe_db_cluster_snapshots(
                    DBClusterSnapshotIdentifier=resource_id
                )
                # If the describe call is successful, it's a DB cluster snapshot
                regional_client.modify_db_cluster_snapshot_attribute(
                    DBClusterSnapshotIdentifier=resource_id,
                    AttributeName="restore",
                    ValuesToRemove=["all"],
                )
            except regional_client.exceptions.DBClusterSnapshotNotFoundFault:
                # If the DB cluster snapshot doesn't exist, it's an instance snapshot
                regional_client.modify_db_snapshot_attribute(
                    DBSnapshotIdentifier=resource_id,
                    AttributeName="restore",
                    ValuesToRemove=["all"],
                )

        except Exception as error:
            logger.error(
                f"{region if 'region' in locals() else 'unknown'} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
        else:
            return True
