from prowler.lib.logger import logger
from prowler.providers.aws.services.s3.s3_client import s3_client


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the S3 bucket's public access settings to block all public access.
    Specifically, this fixer configures the bucket's public access block settings to
    prevent any public access (ACLs and policies). Requires the s3:PutBucketPublicAccessBlock
    permission to modify the public access settings.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:PutBucketPublicAccessBlock",
                "Resource": "*"
            }
        ]
    }
    Args:
        resource_id (str): The S3 bucket name.
        region (str): AWS region where the S3 bucket exists.
    Returns:
        bool: True if the operation is successful (public access is blocked),
              False otherwise.
    """
    try:
        regional_client = s3_client.regional_clients[region]
        regional_client.put_public_access_block(
            Bucket=resource_id,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
