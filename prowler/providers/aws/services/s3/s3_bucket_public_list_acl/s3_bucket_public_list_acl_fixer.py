from prowler.lib.logger import logger
from prowler.providers.aws.services.s3.s3_client import s3_client


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the S3 bucket ACL to restrict public read access.
    Specifically, this fixer sets the ACL of the bucket to 'private' to prevent
    any public access to the S3 bucket.
    Requires the s3:PutBucketAcl permission.

    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:PutBucketAcl",
                "Resource": "*"
            }
        ]
    }

    Args:
        resource_id (str): The S3 bucket name.
        region (str): AWS region where the S3 bucket exists.

    Returns:
        bool: True if the operation is successful (bucket access is updated), False otherwise.
    """
    try:
        regional_client = s3_client.regional_clients[region]
        regional_client.put_bucket_acl(Bucket=resource_id, ACL="private")
    except Exception as error:
        logger.exception(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
