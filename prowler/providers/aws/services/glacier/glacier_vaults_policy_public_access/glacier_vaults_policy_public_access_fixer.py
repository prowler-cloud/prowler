import json

from prowler.lib.logger import logger
from prowler.providers.aws.services.glacier.glacier_client import glacier_client


def _allows_access_to_everyone(statement: dict) -> bool:
    """
    Check if a vault access policy statement allows access to everyone, following the same logic as the check.
    Args:
        statement (dict): The vault access policy statement.
    Returns:
        bool: True if the statement allows access to everyone, False otherwise.
    """
    if statement.get("Effect") != "Allow":
        return False
    principal = statement.get("Principal", {})
    return (
        "*" in principal
        or ("AWS" in principal and "*" in principal["AWS"])
        or ("CanonicalUser" in principal and "*" in principal["CanonicalUser"])
    )


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the Glacier vault's policy to remove public access.
    Specifically, this fixer removes the statements that allow access to everyone and keeps the rest of the policy,
    such as grants to specific accounts or Deny statements. If no statement is left, the policy is deleted.
    Requires the glacier:GetVaultAccessPolicy, glacier:SetVaultAccessPolicy and glacier:DeleteVaultAccessPolicy permissions.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "glacier:GetVaultAccessPolicy",
                    "glacier:SetVaultAccessPolicy",
                    "glacier:DeleteVaultAccessPolicy"
                ],
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
        policy = json.loads(
            regional_client.get_vault_access_policy(vaultName=resource_id)["policy"][
                "Policy"
            ]
        )
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        remaining_statements = [
            statement
            for statement in statements
            if not _allows_access_to_everyone(statement)
        ]

        if remaining_statements:
            policy["Statement"] = remaining_statements
            regional_client.set_vault_access_policy(
                vaultName=resource_id, policy={"Policy": json.dumps(policy)}
            )
        else:
            regional_client.delete_vault_access_policy(vaultName=resource_id)

    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
