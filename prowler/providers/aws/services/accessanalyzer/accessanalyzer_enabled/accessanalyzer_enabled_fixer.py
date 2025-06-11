from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.accessanalyzer.accessanalyzer_client import (
    accessanalyzer_client,
)


class AccessAnalyzerEnabledFixer(AWSFixer):
    """
    Fixer for enabling Access Analyzer in a region.
    """

    def __init__(self):
        super().__init__(
            description="Enable Access Analyzer in a region",
            cost_impact=False,
            cost_description=None,
            service="accessanalyzer",
            iam_policy_required={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "access-analyzer:CreateAnalyzer",
                        "Resource": "*",
                    }
                ],
            },
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Enable Access Analyzer in a region.
        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix
            **kwargs: region (if finding is not provided)
        Returns:
            bool: True if Access Analyzer is enabled, False otherwise
        """
        try:
            if finding:
                region = finding.region
            else:
                region = kwargs.get("region")

            if not region:
                raise ValueError("Region is required")

            # Show the fixing message
            super().fix(region=region)

            regional_client = accessanalyzer_client.regional_clients[region]
            regional_client.create_analyzer(
                analyzerName=accessanalyzer_client.fixer_config.get(
                    "accessanalyzer_enabled", {}
                ).get("AnalyzerName", "DefaultAnalyzer"),
                type=accessanalyzer_client.fixer_config.get(
                    "accessanalyzer_enabled", {}
                ).get("AnalyzerType", "ACCOUNT_UNUSED_ACCESS"),
            )
            return True
        except Exception as error:
            logger.error(
                f"{region if 'region' in locals() else 'unknown'} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
