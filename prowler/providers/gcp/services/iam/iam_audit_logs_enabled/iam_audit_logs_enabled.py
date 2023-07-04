from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_client import (
    cloudresourcemanager_client,
)


class iam_audit_logs_enabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for project in cloudresourcemanager_client.projects:
            report = Check_Report_GCP(self.metadata())
            report.project_id = project.id
            report.location = cloudresourcemanager_client.region
            report.resource_id = project.id
            report.status = "PASS"
            report.status_extended = f"Audit Logs are enabled for project {project.id}"
            if not project.audit_logging:
                report.status = "FAIL"
                report.status_extended = (
                    f"Audit Logs are not enabled for project {project.id}"
                )
            findings.append(report)

        return findings
