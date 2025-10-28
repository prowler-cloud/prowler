from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.logging.logging_client import logging_client
from prowler.providers.gcp.services.monitoring.monitoring_client import (
    monitoring_client,
)


class logging_log_metric_filter_and_alert_for_bucket_permission_changes_enabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        projects_with_metric = set()
        for metric in logging_client.metrics:
            if (
                'resource.type="gcs_bucket" AND protoPayload.methodName="storage.setIamPermissions"'
                in metric.filter
            ):
                metric_name = getattr(metric, "name", None) or "unknown"
                report = Check_Report_GCP(
                    metadata=self.metadata(),
                    resource=metric,
                    resource_id=metric_name,
                    project_id=metric.project_id,
                    location=logging_client.region,
                    resource_name=(
                        metric_name if metric_name != "unknown" else "Log Metric Filter"
                    ),
                )
                projects_with_metric.add(metric.project_id)
                report.status = "FAIL"
                report.status_extended = f"Log metric filter {metric_name} found but no alerts associated in project {metric.project_id}."
                for alert_policy in monitoring_client.alert_policies:
                    for filter in alert_policy.filters:
                        if metric_name in filter:
                            report.status = "PASS"
                            report.status_extended = f"Log metric filter {metric_name} found with alert policy {alert_policy.display_name} associated in project {metric.project_id}."
                            break
                findings.append(report)

        for project in logging_client.project_ids:
            if project not in projects_with_metric:
                project_obj = logging_client.projects.get(project)
                report = Check_Report_GCP(
                    metadata=self.metadata(),
                    resource=project_obj,
                    project_id=project,
                    location=logging_client.region,
                    resource_name=(getattr(project_obj, "name", None) or "GCP Project"),
                )
                report.status = "FAIL"
                report.status_extended = f"There are no log metric filters or alerts associated in project {project}."
                findings.append(report)

        return findings
