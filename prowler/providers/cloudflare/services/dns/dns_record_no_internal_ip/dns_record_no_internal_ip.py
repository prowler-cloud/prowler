import ipaddress

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.dns.dns_client import dns_client


class dns_record_no_internal_ip(Check):
    """Ensure that DNS records do not expose internal or private IP addresses.

    Public DNS records should only contain publicly routable IP addresses.
    Exposing internal, private, loopback, or link-local addresses in DNS records
    can leak information about internal network infrastructure, potentially
    aiding attackers in reconnaissance and targeted attacks against internal
    systems.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the internal IP address exposure check.

        Iterates through all A and AAAA DNS records and checks if they contain
        private, loopback, link-local, or reserved IP addresses that should not
        be exposed publicly.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if the
            record points to a public IP address, or FAIL status if it exposes
            an internal IP address.
        """
        findings = []

        for record in dns_client.records:
            # Only check A and AAAA records
            if record.type not in ("A", "AAAA"):
                continue

            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=record,
            )

            is_internal = self._is_internal_ip(record.content)

            if not is_internal:
                report.status = "PASS"
                report.status_extended = (
                    f"DNS record {record.name} ({record.type}) points to "
                    f"public IP address {record.content}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"DNS record {record.name} ({record.type}) exposes "
                    f"internal IP address {record.content} - information disclosure risk."
                )
            findings.append(report)

        return findings

    def _is_internal_ip(self, ip_str: str) -> bool:
        """Check if IP address is internal/private."""
        try:
            ip = ipaddress.ip_address(ip_str)
            # Check for private, loopback, link-local, or reserved addresses
            return (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_unspecified
            )
        except ValueError:
            # Invalid IP format, assume not internal
            return False
