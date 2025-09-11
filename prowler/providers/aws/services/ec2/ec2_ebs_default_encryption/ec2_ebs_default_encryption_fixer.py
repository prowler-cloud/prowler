from prowler.lib.logger import logger
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


def fixer(region):
    """
    Enable EBS encryption by default in a region. NOTE: Custom KMS keys for EBS Default Encryption may be overwritten.
    Requires the ec2:EnableEbsEncryptionByDefault permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "ec2:EnableEbsEncryptionByDefault",
                "Resource": "*"
            }
        ]
    }
    Args:
        region (str): AWS region
    Returns:
        bool: True if EBS encryption by default is enabled, False otherwise
    """
    try:
        regional_client = ec2_client.regional_clients[region]
        return regional_client.enable_ebs_encryption_by_default()[
            "EbsEncryptionByDefault"
        ]
    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
