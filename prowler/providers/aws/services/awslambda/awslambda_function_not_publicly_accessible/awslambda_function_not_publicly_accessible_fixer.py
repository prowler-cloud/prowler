import json

from prowler.lib.logger import logger
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client
from prowler.providers.aws.services.iam.lib.policy import is_policy_public


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the Lambda function's resource-based policy to remove public access.
    Specifically, this fixer removes the permission statements that grant public access, using the same logic as the check,
    and keeps the rest of the policy, such as grants to specific accounts or AWS services.
    Requires the lambda:GetPolicy and lambda:RemovePermission permissions.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "lambda:GetPolicy",
                    "lambda:RemovePermission"
                ],
                "Resource": "*"
            }
        ]
    }
    Args:
        resource_id (str): The Lambda function name or ARN.
        region (str): AWS region where the Lambda function exists.
    Returns:
        bool: True if the operation is successful (public permissions removed), False otherwise.
    """
    try:
        regional_client = awslambda_client.regional_clients[region]
        policy_response = regional_client.get_policy(FunctionName=resource_id)
        policy = json.loads(policy_response.get("Policy"))
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            statement_id = statement.get("Sid")
            if statement_id and is_policy_public(
                {"Statement": [statement]},
                awslambda_client.audited_account,
                is_cross_account_allowed=True,
            ):
                regional_client.remove_permission(
                    FunctionName=resource_id, StatementId=statement_id
                )

    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
