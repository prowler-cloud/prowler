import json

from prowler.lib.logger import logger
from prowler.providers.aws.services.glacier.glacier_client import glacier_client


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the Glacier vault's policy to remove public access and replace it with trusted account access.
    Specifically, this fixer checks if any statement has a public Principal (e.g., "*" or "AWS": "*")
    and replaces it with the ARN of the trusted AWS account. Requires the glacier:UpdateVaultConfig permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "glacier:UpdateVaultConfig",
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
        account_id = glacier_client.audited_account
        audited_partition = glacier_client.audited_partition

        regional_client = glacier_client.regional_clients[region]

        trusted_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:{audited_partition}:iam::{account_id}:root"
                    },
                    "Action": "glacier:*",
                    "Resource": f"arn:{audited_partition}:glacier:{region}:{account_id}:vaults/{resource_id}",
                }
            ],
        }

        regional_client.set_vault_access_policy(
            vaultName=resource_id,
            policy={"Policy": json.dumps(trusted_policy)},
        )

    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
