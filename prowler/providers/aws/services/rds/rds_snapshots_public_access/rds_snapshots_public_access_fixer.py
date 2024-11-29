from prowler.lib.logger import logger
from prowler.providers.aws.services.rds.rds_client import rds_client


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the attributes of an RDS DB snapshot or DB cluster snapshot to remove public access.
    Specifically, this fixer removes the 'all' value from the 'restore' attribute to prevent the snapshot from being publicly accessible
    for both DB snapshots and DB cluster snapshots. Requires the rds:ModifyDBSnapshotAttribute or rds:ModifyDBClusterSnapshotAttribute permissions.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "rds:ModifyDBSnapshotAttribute",
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": "rds:ModifyDBClusterSnapshotAttribute",
                "Resource": "*"
            }
        ]
    }
    Args:
        resource_id (str): The DB snapshot or DB cluster snapshot identifier.
        region (str): AWS region where the snapshot exists.
    Returns:
        bool: True if the operation is successful (public access is removed), False otherwise.
    """
    try:
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
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
