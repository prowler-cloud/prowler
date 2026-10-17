import json

from botocore.exceptions import ClientError

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


def _apply_statements(
    regional_client, bucket_name: str, policy: dict, statements: list
) -> None:
    """
    Write the bucket policy with the given statements, or delete it if no statement is left.
    Args:
        regional_client: The S3 regional client.
        bucket_name (str): The S3 bucket name.
        policy (dict): The original bucket policy, whose other keys (Version, Id) are kept.
        statements (list): The statements to keep in the policy.
    """
    if statements:
        regional_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps({**policy, "Statement": statements}),
        )
    else:
        regional_client.delete_bucket_policy(Bucket=bucket_name)


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the S3 bucket's policy to remove public write access.
    Specifically, this fixer removes the statements that grant public write access and keeps the rest of the policy,
    such as service principal grants or Deny statements that enforce TLS. If no statement is left, the policy is deleted.
    If S3 rejects the new policy because it is still public (Block Public Access "BlockPublicPolicy" is enabled),
    the remaining public statements are removed as well and a warning lists them.
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

        try:
            _apply_statements(
                regional_client, resource_id, policy, remaining_statements
            )
        except ClientError as error:
            # With S3 Block Public Access "BlockPublicPolicy" enabled, S3 rejects any new policy that is
            # still public (e.g. a public read statement kept from the original policy). The bucket owner
            # does not allow public policies, so remove the remaining public statements too and retry.
            public_statements = [
                statement
                for statement in remaining_statements
                if is_policy_public(
                    {"Statement": [statement]}, s3_client.audited_account
                )
            ]
            if (
                error.response.get("Error", {}).get("Code") != "AccessDenied"
                or not public_statements
            ):
                raise
            logger.warning(
                f"{region} -- S3 rejected the policy of bucket {resource_id} because it is still public, likely due to "
                f"Block Public Access (BlockPublicPolicy). Also removing the public statements: "
                f"{[statement.get('Sid', '<no Sid>') for statement in public_statements]}"
            )
            _apply_statements(
                regional_client,
                resource_id,
                policy,
                [
                    statement
                    for statement in remaining_statements
                    if statement not in public_statements
                ],
            )
    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
