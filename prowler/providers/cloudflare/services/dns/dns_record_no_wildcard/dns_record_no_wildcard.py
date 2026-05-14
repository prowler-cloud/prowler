from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.dns.dns_client import dns_client

# Record types where wildcards pose security risks:
# - A, AAAA: Wildcard resolves any subdomain to an IP, exposing services
# - CNAME: Wildcard aliases any subdomain, potential for subdomain takeover
# - MX: Wildcard accepts mail for any subdomain, potential mail interception
# - SRV: Wildcard exposes services on any subdomain
WILDCARD_RISK_TYPES = {"A", "AAAA", "CNAME", "MX", "SRV"}


class dns_record_no_wildcard(Check):
    """Ensure that wildcard DNS records are not configured for the zone.

    Wildcard DNS records (*.domain.com) match any subdomain that doesn't have
    an explicit record, which can unintentionally expose services or create
    security risks. Attackers may discover hidden services, and wildcard
    certificates combined with wildcard DNS can increase the attack surface
    for subdomain takeover vulnerabilities. Wildcard MX records can allow
    mail interception for arbitrary subdomains.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the wildcard DNS record check.

        Iterates through all security-relevant DNS records (A, AAAA, CNAME, MX, SRV)
        and identifies those configured as wildcard records (starting with *.).
        Wildcard records may expose unintended services or create security risks.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if the
            record is not a wildcard, or FAIL status if it is a wildcard record.
        """
        findings = []

        for record in dns_client.records:
            # Check record types where wildcards pose security risks
            if record.type not in WILDCARD_RISK_TYPES:
                continue

            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=record,
            )

            # Check if record name starts with wildcard
            is_wildcard = record.name.startswith("*.")

            if not is_wildcard:
                report.status = "PASS"
                report.status_extended = f"DNS record {record.name} ({record.type}) is not a wildcard record."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"DNS record {record.name} ({record.type}) is a wildcard record - "
                    f"may expose unintended services."
                )
            findings.append(report)

        return findings
