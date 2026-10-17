import json

from prowler.lib.logger import logger
from prowler.providers.aws.services.iam.lib.policy import is_policy_public
from prowler.providers.aws.services.s3.s3_client import s3_client

# Same actions the s3_bucket_policy_public_write_access check treats as public write access
PUBLIC_WRITE_ACTIONS = [
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:*",
    "s3:Put*",
    "s3:Delete*",
]


def _grants_public_write(statement: dict, account_id: str) -> bool:
    """
    Check if a bucket policy statement grants public write access, following the same logic as the check.
    Args:
        statement (dict): The bucket policy statement.
        account_id (str): The audited AWS account ID.
    Returns:
        bool: True if the statement grants public write access, False otherwise.
    """
    return is_policy_public(
        {"Statement": [statement]},
        account_id,
        not_allowed_actions=PUBLIC_WRITE_ACTIONS,
    )


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the S3 bucket's policy to remove public write access.
    Specifically, this fixer removes the statements that grant public write access and keeps the rest of the policy,
    such as service principal grants or Deny statements that enforce TLS. If no statement is left, the policy is deleted.
    Requires the s3:GetBucketPolicy, s3:PutBucketPolicy and s3:DeleteBucketPolicy permissions.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetBucketPolicy",
                    "s3:PutBucketPolicy",
                    "s3:DeleteBucketPolicy"
                ],
                "Resource": "*"
            }
        ]
    }
    Args:
        resource_id (str): The S3 bucket name.
        region (str): AWS region where the S3 bucket exists.
    Returns:
        bool: True if the operation is successful (policy updated), False otherwise.
    """
    try:
        regional_client = s3_client.regional_clients[region]
        policy = json.loads(
            regional_client.get_bucket_policy(Bucket=resource_id)["Policy"]
        )
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        remaining_statements = [
            statement
            for statement in statements
            if not _grants_public_write(statement, s3_client.audited_account)
        ]

        if remaining_statements:
            policy["Statement"] = remaining_statements
            regional_client.put_bucket_policy(
                Bucket=resource_id, Policy=json.dumps(policy)
            )
        else:
            regional_client.delete_bucket_policy(Bucket=resource_id)
    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
