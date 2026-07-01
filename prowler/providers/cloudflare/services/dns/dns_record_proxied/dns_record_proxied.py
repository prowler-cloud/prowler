from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.dns.dns_client import dns_client

PROXYABLE_TYPES = {"A", "AAAA", "CNAME"}


class dns_record_proxied(Check):
    """Ensure that DNS records are proxied through Cloudflare.

    Proxying DNS records through Cloudflare hides the origin server's IP address
    and provides DDoS protection, WAF capabilities, and performance optimizations.
    Non-proxied (DNS-only) records expose the origin IP directly, bypassing
    Cloudflare's security features and making the origin vulnerable to direct
    attacks.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the DNS record proxy status check.

        Iterates through all proxyable DNS records (A, AAAA, CNAME) and verifies
        that they are configured to be proxied through Cloudflare. Non-proxied
        records bypass Cloudflare's security and performance features.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if the
            record is proxied through Cloudflare, or FAIL status if it is
            DNS-only (not proxied).
        """
        findings = []

        for record in dns_client.records:
            # Only check proxyable record types
            if record.type not in PROXYABLE_TYPES:
                continue

            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=record,
            )

            if record.proxied:
                report.status = "PASS"
                report.status_extended = f"DNS record {record.name} ({record.type}) is proxied through Cloudflare."
            else:
                report.status = "FAIL"
                report.status_extended = f"DNS record {record.name} ({record.type}) is not proxied through Cloudflare."
            findings.append(report)

        return findings
