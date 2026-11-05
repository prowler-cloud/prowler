from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.network.network_client import network_client


class network_reserveip_floating_ip_unattached(Check):
    """Check if E2E Networks floating IPs are attached to nodes."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for ip in network_client.reserved_ips:
            if ip.reserved_type != "FloatingIP":
                continue
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=ip)
            report.status = "PASS"
            report.status_extended = (
                f"Floating IP {ip.ip_address} is attached to node(s)."
            )
            if ip.status != "Attached" or ip.floating_ip_attached_nodes_count == 0:
                report.status = "FAIL"
                report.status_extended = (
                    f"Floating IP {ip.ip_address} is not attached to any node."
                )
            findings.append(report)
        return findings
