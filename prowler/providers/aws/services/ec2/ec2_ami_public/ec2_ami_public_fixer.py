from prowler.lib.logger import logger
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the attributes of an EC2 AMI to remove public access.
    Specifically, this fixer removes the 'all' value from the 'LaunchPermission' attribute
    to prevent the AMI from being publicly accessible.
    Requires the ec2:ModifyImageAttribute permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "ec2:ModifyImageAttribute",
                "Resource": "*"
            }
        ]
    }
    Args:
        resource_id (str): The ID of the EC2 AMI to make private.
        region (str): AWS region where the AMI exists.
    Returns:
        bool: True if the operation is successful (the AMI is no longer publicly accessible), False otherwise.
    """
    try:
        regional_client = ec2_client.regional_clients[region]
        regional_client.modify_image_attribute(
            ImageId=resource_id,
            LaunchPermission={"Remove": [{"Group": "all"}]},
        )
    except Exception as error:
        logger.exception(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
