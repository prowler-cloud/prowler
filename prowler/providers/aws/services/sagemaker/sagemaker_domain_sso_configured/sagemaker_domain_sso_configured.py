from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_domain_sso_configured(Check):
    def execute(self):
        findings = []
        for domain in sagemaker_client.sagemaker_domains:
            report = Check_Report_AWS(metadata=self.metadata(), resource=domain)
            report.status = "PASS"
            report.status_extended = f"SageMaker domain {domain.name} is configured with SSO authentication."
            if domain.auth_mode != "SSO":
                report.status = "FAIL"
                report.status_extended = f"SageMaker domain {domain.name} is not configured with SSO authentication, current mode is {domain.auth_mode}."

            findings.append(report)

        return findings
