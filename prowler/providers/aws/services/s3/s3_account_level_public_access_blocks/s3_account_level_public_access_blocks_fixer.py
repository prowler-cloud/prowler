from prowler.lib.logger import logger
from prowler.providers.aws.services.s3.s3control_client import s3control_client


def fixer(resource_id: str) -> bool:
    """
    Enable S3 Block Public Access for the account. NOTE: By blocking all S3 public access you may break public S3 buckets.
    Requires the s3:PutAccountPublicAccessBlock permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:PutAccountPublicAccessBlock",
                "Resource": "*"
            }
        ]
    }
    Args:
        resource_id (str): The AWS account ID.
    Returns:
        bool: True if S3 Block Public Access is enabled, False otherwise
    """
    try:
        s3control_client.client.put_public_access_block(
            AccountId=resource_id,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
