from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_client import (
    cloudresourcemanager_client,
)


class iam_audit_logs_enabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
<<<<<<< HEAD
        for project in cloudresourcemanager_client.projects:
            report = Check_Report_GCP(self.metadata())
            report.project_id = project.id
            report.location = cloudresourcemanager_client.region
            report.resource_id = project.id
=======
        for project in cloudresourcemanager_client.cloud_resource_manager_projects:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=cloudresourcemanager_client.projects[project.id],
                project_id=project.id,
                location=cloudresourcemanager_client.region,
            )
>>>>>>> e4d234fe0 (fix(azure): remove `resource_name` inside the `Check_Report` (#7420))
            report.status = "PASS"
            report.status_extended = f"Audit Logs are enabled for project {project.id}."
            if not project.audit_logging:
                report.status = "FAIL"
                report.status_extended = (
                    f"Audit Logs are not enabled for project {project.id}."
                )
            findings.append(report)

        return findings
