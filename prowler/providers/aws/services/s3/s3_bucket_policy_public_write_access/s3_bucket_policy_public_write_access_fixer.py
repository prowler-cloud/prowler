from prowler.lib.logger import logger
from prowler.providers.aws.services.s3.s3_client import s3_client


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the S3 bucket's policy to remove public access.
    Specifically, this fixer delete the policy of the public bucket.
    Requires the s3:DeleteBucketPolicy permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:DeleteBucketPolicy",
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

        regional_client.delete_bucket_policy(Bucket=resource_id)

    except Exception as error:
        logger.exception(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
