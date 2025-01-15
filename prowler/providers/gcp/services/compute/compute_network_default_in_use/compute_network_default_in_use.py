from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_network_default_in_use(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        projects_with_default_network = {}

        # Identify projects with the default network
        for network in compute_client.networks:
            if network.name == "default":
                projects_with_default_network[network.project_id] = network

        # Generate reports for all projects
        for project in compute_client.project_ids:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource_metadata=compute_client.projects[project],
                project_id=project,
                resource_id="default",
                resource_name="default",
                location=compute_client.region,
            )
            if project in projects_with_default_network:
                report.status = "FAIL"
                report.status_extended = (
                    f"Default network is in use in project {project}."
                )
                report.resource_metadata = projects_with_default_network[project]
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Default network does not exist in project {project}."
                )

            findings.append(report)

        return findings
