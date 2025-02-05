from prowler.lib.logger import logger
from prowler.providers.aws.services.rds.rds_client import rds_client


def fixer(resource_id: str, region: str) -> bool:
    """
    Modify the attributes of an RDS instance to disable public accessibility.
    Specifically, this fixer sets the 'PubliclyAccessible' attribute to False
    to prevent the RDS instance from being publicly accessible. Requires the rds:ModifyDBInstance permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "rds:ModifyDBInstance",
                "Resource": "*"
            }
        ]
    }
    Args:
        resource_id (str): The DB instance identifier.
        region (str): AWS region where the DB instance exists.
    Returns:
        bool: True if the operation is successful (public access is disabled), False otherwise.
    """
    try:
        regional_client = rds_client.regional_clients[region]
        regional_client.modify_db_instance(
            DBInstanceIdentifier=resource_id,
            PubliclyAccessible=False,
            ApplyImmediately=True,
        )
    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
