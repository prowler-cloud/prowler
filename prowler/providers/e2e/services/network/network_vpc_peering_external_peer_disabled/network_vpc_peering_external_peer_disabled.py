from prowler.lib.check.models import Check, CheckReportE2e
from prowler.providers.e2e.services.network.network_client import network_client


class network_vpc_peering_external_peer_disabled(Check):
    """Check if E2E Cloud VPC peering does not use external peers."""

    def execute(self) -> list[CheckReportE2e]:
        findings = []
        for tunnel in network_client.vpc_tunnels:
            report = CheckReportE2e(metadata=self.metadata(), resource=tunnel)
            report.status = "PASS"
            report.status_extended = (
                f"VPC peering {tunnel.name} does not use an external peer VPC."
            )
            if tunnel.is_peer_vpc_external:
                report.status = "FAIL"
                report.status_extended = (
                    f"VPC peering {tunnel.name} uses an external peer VPC."
                )
            findings.append(report)
        return findings
