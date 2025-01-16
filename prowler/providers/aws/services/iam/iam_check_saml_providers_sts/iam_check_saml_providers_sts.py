from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_check_saml_providers_sts(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        if not iam_client.saml_providers and iam_client.saml_providers is not None:
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=iam_client.saml_providers
            )
            report.resource_id = iam_client.audited_account
            report.resource_arn = iam_client.audited_account_arn
            report.region = iam_client.region
            report.status = "FAIL"
            report.status_extended = "No SAML Providers found."
            findings.append(report)

        for provider in iam_client.saml_providers.values():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=provider
            )
            report.region = iam_client.region
            report.status = "PASS"
            report.status_extended = f"SAML Provider {provider.name} has been found."
            findings.append(report)

        return findings
