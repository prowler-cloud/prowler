from prowler.lib.logger import logger
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.s3.s3_client import s3_client


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the CloudTrail's associated S3 bucket's public access settings to ensure the bucket is not publicly accessible.
    Specifically, this fixer configures the S3 bucket's public access block settings to block all public access.
    Requires the s3:PutBucketPublicAccessBlock permissions.
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
        resource_id (str): The CloudTrail name.
        region (str): AWS region where the CloudTrail and S3 bucket exist.
    Returns:
        bool: True if the operation is successful (policy and ACL updated), False otherwise.
    """
    try:
        regional_client = s3_client.regional_clients[region]
        for trail in cloudtrail_client.trails.values():
            if trail.name == resource_id:
                trail_bucket = trail.s3_bucket

                regional_client.put_public_access_block(
                    Bucket=trail_bucket,
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
