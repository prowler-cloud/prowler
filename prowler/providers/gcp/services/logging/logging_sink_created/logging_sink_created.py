from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.logging.logging_client import logging_client


class logging_sink_created(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        projects_with_logging_sink = {}
        for sink in logging_client.sinks:
            if sink.filter == "all":
                projects_with_logging_sink[sink.project_id] = sink

        for project in logging_client.project_ids:
            if project not in projects_with_logging_sink.keys():
                report = Check_Report_GCP(
                    metadata=self.metadata(),
                    resource=logging_client.projects[project],
                    project_id=project,
                    location=logging_client.region,
                )
                report.status = "FAIL"
                report.status_extended = f"There are no logging sinks to export copies of all the log entries in project {project}."
                findings.append(report)
            else:
                report = Check_Report_GCP(
                    metadata=self.metadata(),
                    resource=projects_with_logging_sink[project],
                    location=logging_client.region,
                )
                report.status = "PASS"
                report.status_extended = f"Sink {projects_with_logging_sink[project].name} is enabled exporting copies of all the log entries in project {project}."
                findings.append(report)
        return findings
