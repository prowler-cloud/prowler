from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_check_saml_providers_sts(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        for provider in iam_client.saml_providers:
            report = Check_Report_AWS(self.metadata())
            provider_name = provider["Arn"].split("/")[1]
            report.resource_id = provider_name
            report.resource_arn = provider["Arn"]
            report.region = iam_client.region
            report.status = "PASS"
            report.status_extended = f"SAML Provider {provider_name} has been found"
            findings.append(report)

        return findings
