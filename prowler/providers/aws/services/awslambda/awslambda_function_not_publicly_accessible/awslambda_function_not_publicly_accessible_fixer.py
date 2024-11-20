import json  # Necesario para decodificar la política si es una cadena JSON

from prowler.lib.logger import logger
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the Lambda function's resource-based policy to remove public access.
    Specifically, this fixer removes the public permission statement from the function's policy.
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
        bool: True if the operation is successful (public access is removed), False otherwise.
    """
    try:
        regional_client = awslambda_client.regional_clients[region]

        # Get the current policy attached to the Lambda function
        policy_response = regional_client.get_policy(FunctionName=resource_id)

        # Check if the policy exists
        policy = policy_response.get("Policy")
        if policy:
            # If the policy is a string (JSON format), decode it into a dictionary
            if isinstance(policy, str):
                policy = json.loads(
                    policy
                )  # Decoding the JSON string into a Python dict

            # Loop through the policy to find the public permission
            statement_id = None
            for statement in policy.get("Statement", []):
                if "Principal" in statement and "*" in statement["Principal"]:
                    statement_id = statement.get(
                        "Sid"
                    )  # Use Sid for unique statement identification
                    break

            # If a public permission is found, remove it
            if statement_id:
                regional_client.remove_permission(
                    FunctionName=resource_id, StatementId=statement_id
                )
            else:
                logger.error(
                    f"{region} -- No public permission found for function {resource_id}"
                )
                return True
        else:
            logger.error(f"{region} -- No policy found for function {resource_id}")
            return True

    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
