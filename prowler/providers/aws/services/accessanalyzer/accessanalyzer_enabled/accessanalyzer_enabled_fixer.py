from typing import Dict, Optional

from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer, FixerMetadata


class AccessAnalyzerEnabledFixer(AWSFixer):
    """Fixer for AccessAnalyzer enabled check"""

    def __init__(
        self, credentials: Optional[Dict] = None, session_config: Optional[Dict] = None
    ):
        super().__init__(credentials, session_config)
        self.service = "accessanalyzer"
        self.regional_clients = ["accessanalyzer"]
        self.iam_policy_required = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "access-analyzer:CreateAnalyzer",
                    "Resource": "*",
                }
            ],
        }

    def _get_metadata(self) -> FixerMetadata:
        return FixerMetadata(
            description="Enable Access Analyzer in a region",
            cost_impact=True,
            cost_description="Enabling Access Analyzer may incur AWS charges",
        )

    def fix(self, finding: Optional[Dict] = None, **kwargs) -> bool:
        """
        Enable Access Analyzer in a region
        Args:
            finding: Finding dictionary (optional)
            **kwargs: Additional arguments (region is required if finding is not provided)
        Returns:
            bool: True if Access Analyzer is enabled, False otherwise
        """
        try:
            region = kwargs.get("region") or (finding and finding.get("Region"))
            if not region:
                raise ValueError("Region is required")

            regional_client = self.client.regional_clients[region]
            regional_client.create_analyzer(
                analyzerName=self.client.fixer_config.get(
                    "accessanalyzer_enabled", {}
                ).get("AnalyzerName", "DefaultAnalyzer"),
                type=self.client.fixer_config.get("accessanalyzer_enabled", {}).get(
                    "AnalyzerType", "ACCOUNT_UNUSED_ACCESS"
                ),
            )
            return True
        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
