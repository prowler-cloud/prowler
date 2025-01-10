from prowler.lib.logger import logger
from prowler.providers.aws.services.kms.kms_client import kms_client


def fixer(resource_id: str, region: str) -> bool:
    """
    Enable CMK rotation. Requires the kms:EnableKeyRotation permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "kms:EnableKeyRotation",
                "Resource": "*"
            }
        ]
    }
    Args:
        resource_id (str): KMS CMK ID
        region (str): AWS region
    Returns:
        bool: True if CMK rotation is enabled, False otherwise
    """
    try:
        regional_client = kms_client.regional_clients[region]
        regional_client.enable_key_rotation(KeyId=resource_id)
    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
