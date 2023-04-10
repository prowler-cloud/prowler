from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.logging.logging_client import logging_client


class logging_sink_created(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        if not logging_client.sinks:
            report = Check_Report_GCP(self.metadata())
            report.project_id = logging_client.project_id
            report.resource_id = logging_client.project_id
            report.resource_name = ""
            report.location = logging_client.region
            report.status = "FAIL"
            report.status_extended = (
                "There are no logging sinks to export copies of all the log entries"
            )
        else:
            for sink in logging_client.sinks:
                report = Check_Report_GCP(self.metadata())
                report.project_id = logging_client.project_id
                report.resource_id = sink.name
                report.resource_name = sink.name
                report.location = logging_client.region
                report.status = "FAIL"
                report.status_extended = f"Sink {sink.name} is enabled but not exporting copies of all the log entries"
                if sink.filter == "all":
                    report.status = "PASS"
                    report.status_extended = f"Sink {sink.name} is enabled exporting copies of all the log entries"
                findings.append(report)

        return findings
