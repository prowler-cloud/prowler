from prowler.lib.logger import logger
from prowler.providers.aws.services.glacier.glacier_client import glacier_client


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the Glacier vault's policy to remove public access.
    Specifically, this fixer delete the vault policy that has public access.
    Requires the glacier:DeleteVaultAccessPolicy permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "glacier:DeleteVaultAccessPolicy",
                "Resource": "*"
            }
        ]
    }
    Args:
        resource_id (str): The Glacier vault name.
        region (str): AWS region where the Glacier vault exists.
    Returns:
        bool: True if the operation is successful (policy updated), False otherwise.
    """
    try:
        regional_client = glacier_client.regional_clients[region]

        regional_client.delete_vault_access_policy(vaultName=resource_id)

    except Exception as error:
        logger.exception(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
