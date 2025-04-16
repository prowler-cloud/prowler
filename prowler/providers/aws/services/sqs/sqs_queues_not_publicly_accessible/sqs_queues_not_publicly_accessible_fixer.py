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
        audited_partition = sqs_client.audited_partition

        regional_client = sqs_client.regional_clients[region]

        queue_name = resource_id.split("/")[-1]

        trusted_policy = {
            "Version": "2012-10-17",
            "Statement": [
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

        regional_client.set_queue_attributes(
            QueueUrl=resource_id,
            Attributes={"Policy": json.dumps(trusted_policy)},
        )

    except Exception as error:
        logger.exception(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
