from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.network.network_client import network_client


class network_reserveip_orphaned_public_ip(Check):
    """Check if E2E Networks public or addon IPs are attached."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for ip in network_client.reserved_ips:
            if ip.reserved_type not in ("PublicIP", "AddonIP"):
                continue
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=ip)
            report.status = "PASS"
            report.status_extended = (
                f"Reserved IP {ip.ip_address} is attached to a resource."
            )
            if ip.status != "Attached" or ip.vm_id is None:
                report.status = "FAIL"
                report.status_extended = (
                    f"Reserved IP {ip.ip_address} is orphaned (status: {ip.status})."
                )
            findings.append(report)
        return findings
