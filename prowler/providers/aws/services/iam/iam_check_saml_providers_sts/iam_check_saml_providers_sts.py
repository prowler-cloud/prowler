from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_check_saml_providers_sts(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        if not iam_client.saml_providers and iam_client.saml_providers is not None:
            report = Check_Report_AWS(self.metadata())
            report.resource_id = iam_client.audited_account
            report.resource_arn = iam_client.audited_account_arn
            report.region = iam_client.region
            report.status = "FAIL"
            report.status_extended = "No SAML Providers found."
            findings.append(report)

        for provider_arn, provider in iam_client.saml_providers.items():
            report = Check_Report_AWS(self.metadata())
            report.resource_id = provider.name
            report.resource_arn = provider_arn
            report.resource_tags = provider.tags
            report.region = iam_client.region
            report.status = "PASS"
            report.status_extended = f"SAML Provider {provider.name} has been found."
            findings.append(report)

        return findings
