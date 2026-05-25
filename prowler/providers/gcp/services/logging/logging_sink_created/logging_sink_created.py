from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.logging.logging_client import logging_client


class logging_sink_created(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []

        # Map project_id -> sink for direct project-level sinks
        projects_with_logging_sink = {}
        for sink in logging_client.sinks:
            if sink.filter == "all" and not sink.include_children:
                projects_with_logging_sink[sink.project_id] = sink

        # Collect org resource names that have a covering sink (includeChildren=True)
        covering_org_sinks = {}
        for sink in logging_client.sinks:
            if sink.filter == "all" and sink.include_children:
                covering_org_sinks[sink.project_id] = sink

        for project in logging_client.project_ids:
            project_obj = logging_client.projects.get(project)

            # Determine whether this project is covered by an org-level sink
            org = getattr(project_obj, "organization", None) if project_obj else None
            org_resource = f"organizations/{org.id}" if org else None
            covering_sink = covering_org_sinks.get(org_resource) if org_resource else None

            if project in projects_with_logging_sink:
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
            elif covering_sink:
                sink_name = getattr(covering_sink, "name", None) or "unknown"
                report = Check_Report_GCP(
                    metadata=self.metadata(),
                    resource=covering_sink,
                    resource_id=sink_name,
                    project_id=project,
                    location=logging_client.region,
                    resource_name=(
                        sink_name if sink_name != "unknown" else "Logging Sink"
                    ),
                )
                report.status = "PASS"
                report.status_extended = f"Sink {sink_name} at organization level is exporting copies of all the log entries in project {project}."
                findings.append(report)
            else:
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
        return findings
