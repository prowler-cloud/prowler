from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_network_default_in_use(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        # Check if default network is in use for each project
        projects_with_default_network = set()
        for network in compute_client.networks:
            if network.name == "default":
                projects_with_default_network.add(network.project_id)
                report = Check_Report_GCP(self.metadata())
                report.project_id = network.project_id
                report.resource_id = "default"
                report.resource_name = "default"
                report.location = "global"
                report.status = "FAIL"
                report.status_extended = (
                    f"Default network is in use in project {network.project_id}"
                )
                findings.append(report)

        for project in compute_client.project_ids:
            if project not in projects_with_default_network:
                report = Check_Report_GCP(self.metadata())
                report.project_id = project
                report.resource_id = "default"
                report.resource_name = "default"
                report.location = "global"
                report.status = "PASS"
                report.status_extended = (
                    f"Default network does not exist in project {project}"
                )

        return findings
