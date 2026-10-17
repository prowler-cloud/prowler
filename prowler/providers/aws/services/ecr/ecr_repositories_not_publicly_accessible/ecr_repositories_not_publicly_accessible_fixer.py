import json
from copy import deepcopy

from prowler.lib.logger import logger
from prowler.providers.aws.services.ecr.ecr_client import ecr_client
from prowler.providers.aws.services.iam.lib.policy import is_policy_public


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the ECR repository's policy to remove public access.
    Specifically, this fixer removes the statements that grant public access, using the same logic as the check,
    and keeps the rest of the policy, such as grants to specific accounts or Deny statements. If no statement is left, the policy is deleted.
    Requires the ecr:GetRepositoryPolicy, ecr:SetRepositoryPolicy and ecr:DeleteRepositoryPolicy permissions.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ecr:GetRepositoryPolicy",
                    "ecr:SetRepositoryPolicy",
                    "ecr:DeleteRepositoryPolicy"
                ],
                "Resource": "*"
            }
        ]
    }
    Args:
        resource_id (str): The ECR repository name.
        region (str): AWS region where the ECR repository exists.
    Returns:
        bool: True if the operation is successful (policy updated), False otherwise.
    """
    try:
        regional_client = ecr_client.regional_clients[region]
        policy = json.loads(
            regional_client.get_repository_policy(repositoryName=resource_id)[
                "policyText"
            ]
        )
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        remaining_statements = [
            statement
            for statement in statements
            if not is_policy_public(
                # is_policy_public normalizes condition keys in place, so check a copy
                {"Statement": [deepcopy(statement)]},
                ecr_client.audited_account,
            )
        ]

        if remaining_statements:
            policy["Statement"] = remaining_statements
            regional_client.set_repository_policy(
                repositoryName=resource_id, policyText=json.dumps(policy)
            )
        else:
            regional_client.delete_repository_policy(repositoryName=resource_id)

    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
