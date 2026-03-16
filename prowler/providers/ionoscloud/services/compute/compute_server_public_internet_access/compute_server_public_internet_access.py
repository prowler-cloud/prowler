from prowler.lib.check.models import Check, CheckReportIonosCloud
from prowler.providers.ionoscloud.services.compute.compute_client import compute_client


class compute_server_public_internet_access(Check):
    """Check if an IONOS Cloud server has any NIC with a public (internet-routable) IP address.

    A server is considered to have public internet access when at least one of its
    Network Interface Cards carries an IP address that is not in a private RFC-1918
    range.  Servers with direct internet exposure should be intentional and should
    be protected by the built-in IONOS Cloud firewall.
    """

    def execute(self) -> list[CheckReportIonosCloud]:
        findings = []

        for server in compute_client.servers:
            report = CheckReportIonosCloud(
                metadata=self.metadata(), resource=server
            )
            report.resource_id = server.id
            report.resource_name = server.name
            report.location = server.location

            public_ips = _get_public_ips(server)

            if public_ips:
                report.status = "FAIL"
                ips_str = ", ".join(public_ips)
                report.status_extended = (
                    f"Server '{server.name}' in DataCenter '{server.datacenter_name}' "
                    f"({server.location}) has public IP(s): {ips_str}. "
                    "Ensure firewall rules restrict inbound access."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Server '{server.name}' in DataCenter '{server.datacenter_name}' "
                    f"({server.location}) has no public internet-facing IP addresses."
                )

            findings.append(report)

        return findings


def _get_public_ips(server) -> list:
    """Return all non-private IPs assigned to any NIC of the server."""
    import ipaddress

    public_ips = []
    for nic in server.nics:
        for ip in nic.ips:
            try:
                addr = ipaddress.ip_address(ip)
                if not addr.is_private and not addr.is_loopback and not addr.is_link_local:
                    public_ips.append(ip)
            except ValueError:
                # Skip malformed or non-parseable IP strings
                logger.debug(f"Skipping malformed IP address: {ip}")
    return public_ips
