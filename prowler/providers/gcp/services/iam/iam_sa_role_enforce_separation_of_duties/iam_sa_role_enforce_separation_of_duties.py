from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_client import (
    cloudresourcemanager_client,
)
from prowler.providers.gcp.services.iam.iam_client import iam_client


class iam_sa_role_enforce_separation_of_duties(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for account in iam_client.service_accounts:
            report = Check_Report_GCP(self.metadata())
            report.project_id = account.project_id
            report.resource_id = account.email
            report.resource_name = account.name
            report.location = iam_client.region
            report.status = "PASS"
            report.status_extended = f"Principle of separation of duties was enforced to Account {account.email}"
            for binding in cloudresourcemanager_client.bindings:
                print(binding)
                if f"serviceAccount:{account.email}" in binding.members and (
                    "roles/iam.serviceAccountUser" in binding.role
                    or "roles/iam.serviceAccountAdmin" in binding.role
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Principle of separation of duties was not enforced to Account {account.email} with role {binding.role}"
            findings.append(report)

        return findings
