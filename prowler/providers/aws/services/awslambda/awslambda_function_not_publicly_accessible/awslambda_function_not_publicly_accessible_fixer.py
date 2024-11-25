import json

from prowler.lib.logger import logger
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


def fixer(resource_id: str, region: str) -> bool:
    """
    Remove the Lambda function's resource-based policy to prevent public access.
    Specifically, this fixer deletes all permission statements associated with the Lambda function's policy.
    Requires the lambda:RemovePermission permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "lambda:RemovePermission",
                "Resource": "*"
            }
        ]
    }
    Args:
        resource_id (str): The Lambda function name or ARN.
        region (str): AWS region where the Lambda function exists.
    Returns:
        bool: True if the operation is successful (policy removed), False otherwise.
    """
    try:
        regional_client = awslambda_client.regional_clients[region]
        policy_response = regional_client.get_policy(FunctionName=resource_id)
        policy = policy_response.get("Policy")
        if policy:
            if isinstance(policy, str):
                policy = json.loads(policy)

            for statement in policy.get("Statement", []):
                statement_id = statement.get("Sid")
                if statement_id:
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
