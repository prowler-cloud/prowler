from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_client import (
    cloudresourcemanager_client,
)


class iam_no_service_roles_at_project_level(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        failed_projects = set()
        for binding in cloudresourcemanager_client.bindings:
            report = Check_Report_GCP(self.metadata())
            report.project_id = binding.project_id
            report.resource_id = binding.role
            report.resource_name = binding.role
            if binding.role in [
                "roles/iam.serviceAccountUser",
                "roles/iam.serviceAccountTokenCreator",
            ]:
                report.status = "FAIL"
                report.status_extended = f"IAM Users assigned to service role '{binding.role}' at project level {binding.project_id}."
                failed_projects.add(binding.project_id)
                findings.append(report)

        for project in cloudresourcemanager_client.project_ids:
            if project not in failed_projects:
                report = Check_Report_GCP(self.metadata())
                report.project_id = project
                report.resource_id = project
                report.resource_name = ""
                report.status = "PASS"
                report.status_extended = f"No IAM Users assigned to service roles at project level {project}."
                findings.append(report)
        return findings
