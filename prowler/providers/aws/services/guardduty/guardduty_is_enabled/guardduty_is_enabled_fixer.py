from prowler.lib.logger import logger
from prowler.providers.aws.services.guardduty.guardduty_client import guardduty_client


def fixer(region):
    """
    Enable GuardDuty in a region. Requires the guardduty:CreateDetector permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "guardduty:CreateDetector",
                "Resource": "*"
            }
        ]
    }
    Args:
        region (str): AWS region
    Returns:
        bool: True if GuardDuty is enabled, False otherwise
    """
    try:
        regional_client = guardduty_client.regional_clients[region]
        regional_client.create_detector(Enable=True)
    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
