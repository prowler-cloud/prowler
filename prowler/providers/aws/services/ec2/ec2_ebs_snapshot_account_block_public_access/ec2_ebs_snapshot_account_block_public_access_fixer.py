from prowler.lib.logger import logger
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


def fixer(region):
    """
    Enable EBS snapshot block public access in a region.
    Requires the ec2:EnableSnapshotBlockPublicAccess permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "ec2:EnableSnapshotBlockPublicAccess",
                "Resource": "*"
            }
        ]
    }
    Args:
        region (str): AWS region
    Returns:
        bool: True if EBS snapshot block public access is enabled, False otherwise
    """
    try:
        regional_client = ec2_client.regional_clients[region]
        state = ec2_client.fixer_config.get(
            "ec2_ebs_snapshot_account_block_public_access", {}
        ).get("State", "block-all-sharing")
        return (
            regional_client.enable_snapshot_block_public_access(State=state)["State"]
            == state
        )
    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
