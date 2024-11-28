import json

from prowler.lib.logger import logger
from prowler.providers.aws.services.s3.s3_client import s3_client


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the S3 bucket's policy to remove public access.
    Specifically, this fixer replaces any policy allowing public access
    with a trusted access policy for the AWS account. Requires the s3:SetBucketPolicy permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:SetBucketPolicy",
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
                }
            ],
        }

        regional_client.put_bucket_policy(
            Bucket=resource_id, Policy=json.dumps(trusted_policy)
        )

    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
