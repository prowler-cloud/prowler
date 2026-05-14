from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_client import (
    cloudresourcemanager_client,
)


class cloudstorage_audit_logs_enabled(Check):
    """
    Ensure GCP Cloud Storage data access audit logs are enabled.

    - PASS: Project has audit config for storage.googleapis.com or allServices with
      DATA_READ and DATA_WRITE log types enabled.
    - FAIL: Project is missing audit config for Cloud Storage,
      or missing DATA_READ or DATA_WRITE log types.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []

        for project in cloudresourcemanager_client.cloud_resource_manager_projects:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=cloudresourcemanager_client.projects[project.id],
                project_id=project.id,
                location=cloudresourcemanager_client.region,
                resource_name=(
                    cloudresourcemanager_client.projects[project.id].name
                    if cloudresourcemanager_client.projects[project.id].name
                    else "GCP Project"
                ),
            )

            log_types_set = set()
            for config in project.audit_configs:
                if config.service in ["storage.googleapis.com", "allServices"]:
                    log_types_set.update(config.log_types)

            required_logs = {"DATA_READ", "DATA_WRITE"}

            if project.audit_logging:
                if required_logs.issubset(log_types_set):
                    report.status = "PASS"
                    report.status_extended = f"Project {project.id} has Data Access audit logs (DATA_READ and DATA_WRITE) enabled for Cloud Storage."
                else:
                    report.status = "FAIL"
                    if not log_types_set:
                        report.status_extended = f"Project {project.id} has Audit Logs enabled for other services but not for Cloud Storage."
                    else:
                        report.status_extended = (
                            f"Project {project.id} has Audit Logs enabled for Cloud Storage but is missing some required log types"
                            f"(missing: {', '.join(sorted(required_logs - log_types_set))})."
                        )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {project.id} does not have Audit Logs enabled."
                )

            findings.append(report)

        return findings
