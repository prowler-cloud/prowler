from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import (
    sagemaker_client,
)


class sagemaker_domain_vpc_only_enabled(Check):
    """Ensure that SageMaker Domains use VPC-only network access."""

    def execute(self) -> list[Check_Report_AWS]:
        """Evaluate each SageMaker Domain network access configuration.

        Returns:
            list[Check_Report_AWS]: Findings for the discovered SageMaker Domains.
        """
        findings = []

        for domain in sagemaker_client.sagemaker_domains:
            report = Check_Report_AWS(metadata=self.metadata(), resource=domain)

            if not domain.details_retrieved:
                report.status = "MANUAL"
                report.status_extended = (
                    f"SageMaker domain {domain.name} details could not be retrieved; "
                    "manual review is required to verify VPC-only network access."
                )
            elif domain.app_network_access_type == "VpcOnly":
                report.status = "PASS"
                report.status_extended = (
                    f"SageMaker domain {domain.name} uses VPC-only network access."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"SageMaker domain {domain.name} does not use VPC-only network access."

            findings.append(report)

        return findings
