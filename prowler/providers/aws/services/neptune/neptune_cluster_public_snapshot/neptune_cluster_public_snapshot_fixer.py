from prowler.lib.logger import logger
from prowler.providers.aws.services.neptune.neptune_client import neptune_client


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the attributes of a Neptune DB cluster snapshot to remove public access.
    Specifically, this fixer removes the 'all' value from the 'restore' attribute to
    prevent the snapshot from being publicly accessible. Requires the rds:ModifyDBClusterSnapshotAttribute permissions.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "rds:ModifyDBClusterSnapshotAttribute",
                "Resource": "*"
            }
        ]
    }
    Args:
        resource_id (str): The DB cluster snapshot identifier.
        region (str): AWS region where the snapshot exists.
    Returns:
        bool: True if the operation is successful (public access is removed), False otherwise.
    """
    try:
        regional_client = neptune_client.regional_clients[region]
        regional_client.modify_db_cluster_snapshot_attribute(
            DBClusterSnapshotIdentifier=resource_id,
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
