from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.serviceusage.serviceusage_client import (
    serviceusage_client,
)


class gcr_container_scanning_enabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for project_id in serviceusage_client.project_ids:
            report = Check_Report_GCP(self.metadata())
            report.project_id = project_id
            report.resource_id = "containerscanning.googleapis.com"
            report.resource_name = "GCR Container Scanning"
            report.location = serviceusage_client.region
            report.status = "FAIL"
            report.status_extended = (
                f"GCR Container Scanning is not enabled in project {project_id}."
            )
            for active_service in serviceusage_client.active_services.get(
                project_id, []
            ):
                if active_service.name == "containerscanning.googleapis.com":
                    report.status = "PASS"
                    report.status_extended = (
                        f"GCR Container Scanning is enabled in project {project_id}."
                    )
                    break
            findings.append(report)

        return findings
