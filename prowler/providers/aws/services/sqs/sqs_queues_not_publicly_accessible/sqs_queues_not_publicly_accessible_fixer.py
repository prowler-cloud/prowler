import json

from prowler.lib.logger import logger
from prowler.providers.aws.services.sqs.sqs_client import sqs_client


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the SQS queue's resource-based policy to remove public access and replace with trusted account access.
    Specifically, this fixer checks if any statement has a public Principal (e.g., "*" or "CanonicalUser")
    and replaces it with the ARN of the trusted AWS account.
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

        regional_client = sqs_client.regional_clients[region]

        policy_response = regional_client.get_queue_attributes(
            QueueUrl=resource_id, AttributeNames=["Policy"]
        )

        policy = json.loads(policy_response.get("Attributes", {}).get("Policy"))

        for statement in policy.get("Statement", []):
            if "Principal" in statement and (
                "*" in statement["Principal"]
                or (
                    "AWS" in statement["Principal"]
                    and "*" in statement["Principal"]["AWS"]
                )
                or (
                    "CanonicalUser" in statement["Principal"]
                    and "*" in statement["Principal"]["CanonicalUser"]
                )
            ):
                statement["Principal"] = {"AWS": f"arn:aws:iam::{account_id}:root"}
                statement["Action"] = "sqs:*"
                statement["Resource"] = (
                    f"arn:aws:sqs:{region}:{account_id}:{resource_id}"
                )

        regional_client.set_queue_attributes(
            QueueUrl=resource_id,
            Attributes={"Policy": json.dumps(policy)},
        )

    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
