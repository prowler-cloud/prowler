from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_endpoint_config_kms_encryption_enabled(Check):
    """Ensure SageMaker endpoint configurations use a customer-managed KMS key."""

    def execute(self) -> List[Check_Report_AWS]:
        """Return PASS/FAIL findings for each SageMaker endpoint configuration."""
        findings = []
        for endpoint_config in sagemaker_client.endpoint_configs.values():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource=endpoint_config
            )
            report.status = "PASS"
            report.status_extended = (
                f"Sagemaker Endpoint Config {endpoint_config.name} has KMS encryption enabled."
            )
            if not endpoint_config.kms_key_id:
                report.status = "FAIL"
                report.status_extended = (
                    f"Sagemaker Endpoint Config {endpoint_config.name} has KMS encryption disabled."
                )

            findings.append(report)

        return findings
