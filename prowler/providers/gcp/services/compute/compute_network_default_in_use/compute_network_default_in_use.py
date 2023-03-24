from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_network_default_in_use(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        report = Check_Report_GCP(self.metadata())
        report.project_id = compute_client.project_id
        report.resource_id = "default"
        report.resource_name = "default"
        report.location = "global"
        report.status = "PASS"
        report.status_extended = "Default network does not exist"
        for network in compute_client.networks:
            if network.name == "default":
                report.status = "FAIL"
                report.status_extended = "Default network is in use"

        findings.append(report)

        return findings
