import json

from prowler.lib.logger import logger
from prowler.providers.aws.services.iam.iam_client import iam_client


def fixer(resource_arn: str) -> bool:
    """
    Restricts access to a compromised AWS entity by attaching a deny-all inline policy to the user or role.

    Requires the following permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "iam:PutUserPolicy",
                    "iam:PutRolePolicy",
                ],
                "Resource": "*"
            }
        ]
    }

    Args:
        resource_arn (str): The ARN of the compromised AWS entity (IAM User or Role).

    Returns:
        bool: True if the fix was applied successfully, False otherwise.
    """
    try:
        if ":user/" in resource_arn:
            entity_type = "user"
            entity_name = resource_arn.split("/")[-1]
        elif ":role/" in resource_arn:
            entity_type = "role"
            entity_name = resource_arn.split("/")[-1]
        else:
            return False

        deny_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
        }

        policy_name = "DenyAllAccess"

        if entity_type == "user":
            iam_client.client.put_user_policy(
                UserName=entity_name,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(deny_policy),
            )
            logger.info(f"Applied Deny policy to user {entity_name}")

        elif entity_type == "role":
            iam_client.client.put_role_policy(
                RoleName=entity_name,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(deny_policy),
            )
            logger.info(f"Applied Deny policy to role {entity_name}")

        return True

    except Exception as error:
        logger.exception(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
