from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_domain_sso_configured(Check):
    def execute(self):
        findings = []
        for domain in sagemaker_client.sagemaker_domains:
            report = Check_Report_AWS(metadata=self.metadata(), resource=domain)
            if domain.auth_mode == "SSO":
                if (
                    domain.single_sign_on_managed_application_instance_id
                    or domain.single_sign_on_application_arn
                ):
                    report.status = "PASS"
                    report.status_extended = f"SageMaker domain {domain.name} is configured with SSO authentication and is associated with an IAM Identity Center instance."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"SageMaker domain {domain.name} is configured with SSO authentication but is not associated with an IAM Identity Center instance."
            else:
                report.status = "FAIL"
                current_mode = domain.auth_mode if domain.auth_mode else "unknown"
                report.status_extended = f"SageMaker domain {domain.name} is not configured with SSO authentication, current mode is {current_mode}."

            findings.append(report)

        return findings
