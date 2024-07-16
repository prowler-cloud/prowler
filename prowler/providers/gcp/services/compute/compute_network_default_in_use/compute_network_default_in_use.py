from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_network_default_in_use(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        projects_with_default_network = set()

        # Identify projects with the default network
        for network in compute_client.networks:
            if network.name == "default":
                projects_with_default_network.add(network.project_id)

        # Generate reports for all projects
        for project in compute_client.project_ids:
            report = Check_Report_GCP(self.metadata())
            report.project_id = project
            report.resource_id = "default"
            report.resource_name = "default"
            report.location = "global"

            if project in projects_with_default_network:
                report.status = "FAIL"
                report.status_extended = (
                    f"Default network is in use in project {project}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Default network does not exist in project {project}."
                )

            findings.append(report)

        return findings
