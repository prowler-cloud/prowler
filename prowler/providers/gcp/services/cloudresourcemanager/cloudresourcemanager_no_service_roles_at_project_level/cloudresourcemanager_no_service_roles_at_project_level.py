from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_client import (
    cloudresourcemanager_client,
)


class cloudresourcemanager_no_service_roles_at_project_level(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for binding in cloudresourcemanager_client.bindings:
            report = Check_Report_GCP(self.metadata())
            report.project_id = cloudresourcemanager_client.project_id
            report.resource_id = binding.role
            report.resource_name = binding.role
            report.status = "PASS"
            report.status_extended = (
                "No IAM Users assigned to service roles ate project level."
            )
            if binding.role in [
                "roles/iam.serviceAccountUser",
                "roles/iam.serviceAccountTokenCreator",
            ]:
                report.status = "FAIL"
                report.status_extended = f"IAM Users assigned to service role '{binding.role}' ate project level."
            findings.append(report)

        return findings
