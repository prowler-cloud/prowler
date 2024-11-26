import json

from prowler.lib.logger import logger
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


def fixer(resource_id: str, region: str) -> bool:
    """
    Remove the Lambda function's resource-based policy to prevent public access and add a new permission for the account.
    Specifically, this fixer deletes all permission statements associated with the Lambda function's policy and then adds a new permission.
    Requires the lambda:RemovePermission and lambda:AddPermission permissions.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "lambda:RemovePermission",
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": "lambda:AddPermission",
                "Resource": "*"
            }
        ]
    }
    Args:
        resource_id (str): The Lambda function name or ARN.
        region (str): AWS region where the Lambda function exists.
    Returns:
        bool: True if the operation is successful (policy removed and permission added), False otherwise.
    """
    try:
        account_id = awslambda_client.audited_account

        regional_client = awslambda_client.regional_clients[region]
        policy_response = regional_client.get_policy(FunctionName=resource_id)
        policy = json.loads(policy_response.get("Policy"))

        for statement in policy.get("Statement", []):
            statement_id = statement.get("Sid")
            if statement_id:
                regional_client.remove_permission(
                    FunctionName=resource_id, StatementId=statement_id
                )

        regional_client.add_permission(
            FunctionName=resource_id,
            StatementId="ProwlerFixerStatement",
            Principal=account_id,
            Action="lambda:InvokeFunction",
        )

    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
