from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.serviceusage.serviceusage_client import (
    serviceusage_client,
)


class serviceusage_cloudasset_inventory_enabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for project_id in serviceusage_client.project_ids:
            report = Check_Report_GCP(self.metadata())
            report.project_id = project_id
            report.resource_id = "cloudasset.googleapis.com"
            report.resource_name = "Cloud Asset Inventory"
            report.location = serviceusage_client.region
            report.status = "FAIL"
            report.status_extended = (
                f"Cloud Asset Inventory is not enabled in project {project_id}"
            )
            for active_service in serviceusage_client.active_services.get(
                project_id, []
            ):
                if active_service.name == "cloudasset.googleapis.com":
                    report.status = "PASS"
                    report.status_extended = (
                        f"Cloud Asset Inventory is enabled in project {project_id}"
                    )
                    break
            findings.append(report)

        return findings
