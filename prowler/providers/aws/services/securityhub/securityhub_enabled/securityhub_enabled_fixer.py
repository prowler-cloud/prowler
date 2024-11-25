from prowler.lib.logger import logger
from prowler.providers.aws.services.securityhub.securityhub_client import (
    securityhub_client,
)


def fixer(region):
    """
    Enable Security Hub in a region. Requires the securityhub:EnableSecurityHub permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "securityhub:EnableSecurityHub",
                "Resource": "*"
            }
        ]
    }
    Args:
        region (str): AWS region
    Returns:
        bool: True if Security Hub is enabled, False otherwise
    """
    try:
        regional_client = securityhub_client.regional_clients[region]
        regional_client.enable_security_hub(
            EnableDefaultStandards=securityhub_client.fixer_config.get(
                "securityhub_enabled", {}
            ).get("EnableDefaultStandards", True)
        )
    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
