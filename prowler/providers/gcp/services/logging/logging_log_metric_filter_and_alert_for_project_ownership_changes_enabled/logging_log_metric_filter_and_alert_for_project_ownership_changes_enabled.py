from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.logging.logging_client import logging_client
from prowler.providers.gcp.services.monitoring.monitoring_client import (
    monitoring_client,
)


class logging_log_metric_filter_and_alert_for_project_ownership_changes_enabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        report = Check_Report_GCP(self.metadata())
        report.project_id = logging_client.project_id
        report.resource_id = ""
        report.resource_name = ""
        report.location = logging_client.region
        report.status = "FAIL"
        report.status_extended = "There are no log metric filters or alerts associated."
        if logging_client.metrics:
            for metric in logging_client.metrics:
                if (
                    '(protoPayload.serviceName="cloudresourcemanager.googleapis.com") AND (ProjectOwnership OR projectOwnerInvitee) OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="REMOVE" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner") OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")'
                    in metric.filter
                ):
                    report = Check_Report_GCP(self.metadata())
                    report.project_id = logging_client.project_id
                    report.resource_id = metric.name
                    report.resource_name = metric.name
                    report.location = logging_client.region
                    report.status = "FAIL"
                    report.status_extended = f"Log metric filter {metric.name} found but no alerts associated."
                    for alert_policy in monitoring_client.alert_policies:
                        for filter in alert_policy.filters:
                            if metric.name in filter:
                                report.status = "PASS"
                                report.status_extended = f"Log metric filter {metric.name} found with alert policy {alert_policy.display_name} associated."
                                break
        findings.append(report)

        return findings
