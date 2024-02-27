from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.serviceusage.serviceusage_client import (
    serviceusage_client,
)


class artifacts_container_analysis_enabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for project_id in serviceusage_client.project_ids:
            report = Check_Report_GCP(self.metadata())
            report.project_id = project_id
            report.resource_id = "containeranalysis.googleapis.com"
            report.resource_name = "AR Container Analysis"
            report.location = serviceusage_client.region
            report.status = "FAIL"
            report.status_extended = (
                f"AR Container Analysis is not enabled in project {project_id}."
            )
            for active_service in serviceusage_client.active_services.get(
                project_id, []
            ):
                if active_service.name == "containeranalysis.googleapis.com":
                    report.status = "PASS"
                    report.status_extended = (
                        f"AR Container Analysis is enabled in project {project_id}."
                    )
                    break
            findings.append(report)

        return findings
