from prowler.lib.logger import logger
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the attributes of an EBS snapshot to remove public access.
    Specifically, this fixer removes the 'all' value from the 'createVolumePermission' attribute to
    prevent the snapshot from being publicly accessible. Requires the ec2:ModifySnapshotAttribute permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "ec2:ModifySnapshotAttribute",
                "Resource": "*"
            }
        ]
    }
    Args:
        resource_id (str): The snapshot identifier.
        region (str): AWS region where the snapshot exists.
    Returns:
        bool: True if the operation is successful (public access is removed), False otherwise.
    """
    try:
        regional_client = ec2_client.regional_clients[region]
        regional_client.modify_snapshot_attribute(
            SnapshotId=resource_id,
            Attribute="createVolumePermission",
            OperationType="remove",
            GroupNames=["all"],
        )
    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
