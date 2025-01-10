from prowler.lib.logger import logger
from prowler.providers.aws.services.kms.kms_client import kms_client


def fixer(resource_id: str, region: str) -> bool:
    """
    Cancel the scheduled deletion of a KMS key.
    Specifically, this fixer calls the 'cancel_key_deletion' method to restore the KMS key's availability if it is marked for deletion.
    Requires the kms:CancelKeyDeletion permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "kms:CancelKeyDeletion",
                "Resource": "*"
            }
        ]
    }
    Args:
        resource_id (str): The ID of the KMS key to cancel the deletion for.
        region (str): AWS region where the KMS key exists.
    Returns:
        bool: True if the operation is successful (deletion cancellation is completed), False otherwise.
    """
    try:
        regional_client = kms_client.regional_clients[region]
        regional_client.cancel_key_deletion(KeyId=resource_id)
    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
