from prowler.lib.logger import logger
from prowler.providers.aws.services.accessanalyzer.accessanalyzer_client import (
    accessanalyzer_client,
)


def fixer(region):
    """
    Enable Access Analyzer in a region. Requires the access-analyzer:CreateAnalyzer permission.
    Permissions:
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "access-analyzer:CreateAnalyzer",
                "Resource": "*"
            }
        ]
    }
    Args:
        region (str): AWS region
    Returns:
        bool: True if Access Analyzer is enabled, False otherwise
    """
    try:
        regional_client = accessanalyzer_client.regional_clients[region]
        regional_client.create_analyzer(
            analyzerName=accessanalyzer_client.fixer_config.get(
                "accessanalyzer_enabled", {}
            ).get("AnalyzerName", "DefaultAnalyzer"),
            type=accessanalyzer_client.fixer_config.get(
                "accessanalyzer_enabled", {}
            ).get("AnalyzerType", "ACCOUNT_UNUSED_ACCESS"),
        )
    except Exception as error:
        logger.error(
            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    else:
        return True
