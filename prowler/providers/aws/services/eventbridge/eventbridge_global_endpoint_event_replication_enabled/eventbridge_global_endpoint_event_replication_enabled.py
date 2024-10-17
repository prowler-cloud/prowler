from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.eventbridge.eventbridge_client import (
    eventbridge_client,
)


class eventbridge_global_endpoint_event_replication_enabled(Check):
    def execute(self):
        findings = []
        for endpoint in eventbridge_client.endpoints.values():
            report = Check_Report_AWS(self.metadata())
            report.status = "PASS"
            report.status_extended = f"EventBridge global endpoint {endpoint.name} has event replication enabled."
            report.resource_id = endpoint.name
            report.resource_arn = endpoint.arn
            report.resource_tags = endpoint.tags
            report.region = endpoint.region
            if endpoint.replication_state == "DISABLED":
                report.status = "FAIL"
                report.status_extended = f"EventBridge global endpoint {endpoint.name} does not have event replication enabled."
            findings.append(report)
        return findings
