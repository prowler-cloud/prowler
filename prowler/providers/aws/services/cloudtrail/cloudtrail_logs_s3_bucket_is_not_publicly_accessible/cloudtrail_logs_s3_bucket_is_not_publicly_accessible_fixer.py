import json

from prowler.lib.logger import logger
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.s3.s3_client import s3_client


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the CloudTrail's associated S3 bucket's policy and public access settings to ensure the bucket is not publicly accessible.
    Specifically, this fixer:
    1. Modifies the S3 bucket's policy to remove any public access.
    2. Configures the S3 bucket's public access block settings to block all public access.
    Requires the s3:SetBucketPolicy and s3:PutBucketAcl permissions.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:SetBucketPolicy",
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": "s3:PutBucketAcl",
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
        trail = cloudtrail_client.trails.get(resource_id)
        if not trail:
            logger.error(f"{region} -- CloudTrail {resource_id} not found.")
            return False

        trail_bucket = trail.s3_bucket

        regional_client = s3_client.regional_clients[region]
        account_id = s3_client.audited_account
        audited_partition = s3_client.audited_partition

        trusted_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ProwlerFixerStatement",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:{audited_partition}:iam::{account_id}:root"
                    },
                    "Action": "s3:*",
                    "Resource": f"arn:{audited_partition}:s3:::{trail_bucket}/*",
                }
            ],
        }

        regional_client.put_bucket_policy(
            Bucket=trail_bucket, Policy=json.dumps(trusted_policy)
        )

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
