import json

from prowler.lib.logger import logger
from prowler.providers.aws.services.iam.lib.policy import is_condition_block_restrictive
from prowler.providers.aws.services.sqs.sqs_client import sqs_client


def _is_public_statement(statement: dict, account_id: str) -> bool:
    """
    Check if a queue policy statement grants public access, following the same logic as the check.
    Args:
        statement (dict): The policy statement.
        account_id (str): The audited AWS account ID.
    Returns:
        bool: True if the statement grants public access, False otherwise.
    """
    principal = statement.get("Principal")
    if statement.get("Effect") != "Allow" or not principal:
        return False
    if not (
        "*" in principal
        or ("AWS" in principal and "*" in principal["AWS"])
        or ("CanonicalUser" in principal and "*" in principal["CanonicalUser"])
    ):
        return False
    if "Condition" in statement:
        return not is_condition_block_restrictive(
            statement["Condition"], account_id, True
        )
    return True


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the SQS queue's resource-based policy to remove public access and replace with trusted account access.
    Specifically, this fixer removes the statements that have a public Principal (e.g., "*" or "CanonicalUser")
    and adds a statement granting access to the ARN of the trusted AWS account. Other statements are kept.
    Requires the sqs:SetQueueAttributes permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sqs:SetQueueAttributes",
                "Resource": "*"
            }
        ]
    }
    Args:
        resource_id (str): The SQS queue name or ARN.
        region (str): AWS region where the SQS queue exists.
    Returns:
        bool: True if the operation is successful (policy updated), False otherwise.
    """
    try:
        account_id = sqs_client.audited_account
        audited_partition = sqs_client.audited_partition

        regional_client = sqs_client.regional_clients[region]

        queue_name = resource_id.split("/")[-1]

        current_policy = {}
        for queue in sqs_client.queues:
            if queue.id == resource_id and queue.policy:
                current_policy = queue.policy
        statements = current_policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        trusted_policy = {
            "Version": current_policy.get("Version", "2012-10-17"),
            "Statement": [
                statement
                for statement in statements
                if not _is_public_statement(statement, account_id)
                and statement.get("Sid") != "ProwlerFixerStatement"
            ]
            + [
                {
                    "Sid": "ProwlerFixerStatement",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": account_id,
                    },
                    "Action": "sqs:*",
                    "Resource": f"arn:{audited_partition}:sqs:{region}:{account_id}:{queue_name}",
                }
            ],
        }
        if "Id" in current_policy:
            trusted_policy["Id"] = current_policy["Id"]

        regional_client.set_queue_attributes(
            QueueUrl=resource_id,
            Attributes={"Policy": json.dumps(trusted_policy)},
        )

    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
