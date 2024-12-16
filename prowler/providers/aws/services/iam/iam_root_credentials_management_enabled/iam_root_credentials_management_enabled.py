from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)


class iam_root_credentials_management_enabled(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        if (
            organizations_client.organization
            and organizations_client.organization.status == "ACTIVE"
            and iam_client.organization_features is not None
        ):
            report = Check_Report_AWS(self.metadata())
            report.region = iam_client.region
            report.resource_arn = iam_client.audited_account_arn
            report.resource_id = iam_client.audited_account
            if "RootCredentialsManagement" in iam_client.organization_features:
                report.status = "PASS"
                report.status_extended = "Root credentials management is enabled."
            else:
                report.status = "FAIL"
                report.status_extended = "Root credentials management is not enabled."
            findings.append(report)

        return findings
