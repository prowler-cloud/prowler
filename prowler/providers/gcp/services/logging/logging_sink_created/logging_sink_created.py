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
                project_obj = logging_client.projects.get(project)
                report = Check_Report_GCP(
                    metadata=self.metadata(),
                    resource=project_obj,
                    resource_id=project,
                    project_id=project,
                    location=logging_client.region,
                    resource_name=(getattr(project_obj, "name", None) or "GCP Project"),
                )
                report.status = "FAIL"
                report.status_extended = f"There are no logging sinks to export copies of all the log entries in project {project}."
                findings.append(report)
            else:
                sink = projects_with_logging_sink[project]
                sink_name = getattr(sink, "name", None) or "unknown"
                report = Check_Report_GCP(
                    metadata=self.metadata(),
                    resource=sink,
                    resource_id=sink_name,
                    project_id=project,
                    location=logging_client.region,
                    resource_name=(
                        sink_name if sink_name != "unknown" else "Logging Sink"
                    ),
                )
                report.status = "PASS"
                report.status_extended = f"Sink {sink_name} is enabled exporting copies of all the log entries in project {project}."
                findings.append(report)
        return findings
