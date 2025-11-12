from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_client import (
    cloudresourcemanager_client,
)
from prowler.providers.gcp.services.cloudstorage.cloudstorage_client import (
    cloudstorage_client,
)


class cloudstorage_bucket_data_access_audit_logs_enabled(Check):
    """
    Ensure GCP Cloud Storage data access audit logs are enabled.

    - PASS: Project has audit config for storage.googleapis.com with
      DATA_READ and DATA_WRITE log types enabled.
    - FAIL: Project is missing audit config for storage.googleapis.com,
      or missing DATA_READ or DATA_WRITE log types.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []

        # Build lookup dictionary for storage audit log types by project
        # Combine log types from both allServices
        # and storage.googleapis.com
        project_storage_logs = {}
        projects = cloudresourcemanager_client.cloud_resource_manager_projects
        for project in projects:
            log_types_set = set()
            for config in project.audit_configs:
                if config.service in [
                    "storage.googleapis.com",
                    "allServices",
                ]:
                    log_types_set.update(config.log_types)
            if log_types_set:
                project_storage_logs[project.id] = log_types_set

        for bucket in cloudstorage_client.buckets:
            report = Check_Report_GCP(metadata=self.metadata(), resource=bucket)

            log_types = project_storage_logs.get(bucket.project_id, set())
            required_logs = {"DATA_READ", "DATA_WRITE"}

            if required_logs.issubset(log_types):
                report.status = "PASS"
                report.status_extended = (
                    f"Bucket {bucket.name} is covered by project "
                    f"{bucket.project_id} audit logging with DATA_READ "
                    f"and DATA_WRITE enabled."
                )
            else:
                report.status = "FAIL"
                if not log_types:
                    report.status_extended = (
                        f"Bucket {bucket.name} is not covered by audit "
                        f"logging in project {bucket.project_id} "
                        f"(no Cloud Storage audit config found)."
                    )
                else:
                    missing_logs = required_logs - log_types
                    report.status_extended = (
                        f"Bucket {bucket.name} is not fully covered by "
                        f"project {bucket.project_id} audit logging "
                        f"(missing: {', '.join(sorted(missing_logs))})."
                    )

            findings.append(report)
        return findings
