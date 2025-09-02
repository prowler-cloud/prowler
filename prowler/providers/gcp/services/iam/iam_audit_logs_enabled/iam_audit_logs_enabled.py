from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_client import (
    cloudresourcemanager_client,
)


class iam_audit_logs_enabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for project in cloudresourcemanager_client.cloud_resource_manager_projects:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=cloudresourcemanager_client.projects[project.id],
                project_id=project.id,
                location=cloudresourcemanager_client.region,
            )
            report.status = "FAIL"
            report.status_extended = (
                f"Default Audit Logs are not enabled for project {project.id}."
            )
            if project.audit_logging != []:
                for policy in project.audit_logging:
                    DEFAULT_AUDIT_LOGS = [
                        "ADMIN_READ",
                        "DATA_READ",
                        "DATA_WRITE",
                    ]
                    if policy.get("service") == "allServices" and all(
                        log
                        in [
                            log_config.get("logType")
                            for log_config in policy.get("auditLogConfigs", [])
                        ]
                        for log in DEFAULT_AUDIT_LOGS
                    ):
                        report.status = "PASS"
                        report.status_extended = f"Default Audit Logs are enabled for all services in project {project.id}."
                        break
            findings.append(report)

        return findings
