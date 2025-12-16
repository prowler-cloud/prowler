import ipaddress

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.dns.dns_client import dns_client


class dns_record_no_internal_ip(Check):
    def execute(self) -> list[CheckReportCloudflare]:
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
                    f"DNS record '{record.name}' ({record.type}) points to "
                    f"public IP address '{record.content}'."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"DNS record '{record.name}' ({record.type}) exposes "
                    f"internal IP address '{record.content}' - information disclosure risk."
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
