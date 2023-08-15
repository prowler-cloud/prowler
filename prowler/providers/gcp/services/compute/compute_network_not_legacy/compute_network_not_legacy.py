from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_network_not_legacy(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for network in compute_client.networks:
            report = Check_Report_GCP(self.metadata())
            report.project_id = network.project_id
            report.resource_id = network.id
            report.resource_name = network.name
            report.location = compute_client.region
            report.status = "PASS"
            report.status_extended = f"Network {network.name} is not legacy."
            if network.subnet_mode == "legacy":
                report.status = "FAIL"
                report.status_extended = f"Legacy network {network.name} exists."
            findings.append(report)

        return findings
