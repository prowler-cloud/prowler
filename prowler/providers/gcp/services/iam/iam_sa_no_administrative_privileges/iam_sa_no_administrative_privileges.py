from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_client import (
    cloudresourcemanager_client,
)
from prowler.providers.gcp.services.iam.iam_client import iam_client


class iam_sa_no_administrative_privileges(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for account in iam_client.service_accounts:
            report = Check_Report_GCP(self.metadata())
            report.project_id = account.project_id
            report.resource_id = account.email
            report.resource_name = account.name
            report.location = iam_client.region
            report.status = "PASS"
            report.status_extended = (
                f"Account {account.email} has no administrative privileges."
            )
            for binding in cloudresourcemanager_client.bindings:
                if f"serviceAccount:{account.email}" in binding.members and (
                    "admin" in binding.role.lower()
                    or "owner" in binding.role.lower()
                    or "editor" in binding.role.lower()
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Account {account.email} has administrative privileges with {binding.role}."
            findings.append(report)

        return findings
