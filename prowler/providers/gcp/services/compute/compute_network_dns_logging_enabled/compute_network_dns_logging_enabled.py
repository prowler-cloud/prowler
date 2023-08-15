from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client
from prowler.providers.gcp.services.dns.dns_client import dns_client


class compute_network_dns_logging_enabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for network in compute_client.networks:
            report = Check_Report_GCP(self.metadata())
            report.project_id = network.project_id
            report.resource_id = network.id
            report.resource_name = network.name
            report.location = compute_client.region
            report.status = "FAIL"
            report.status_extended = (
                f"Network {network.name} does not have DNS logging enabled."
            )
            for policy in dns_client.policies:
                if network.name in policy.networks and policy.logging:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Network {network.name} has DNS logging enabled."
                    )
                    break
            findings.append(report)

        return findings
