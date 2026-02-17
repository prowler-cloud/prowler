import socket

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.dns.dns_client import dns_client

# Record types that point to hostnames and can be dangling:
# - CNAME: Alias to another hostname
# - MX: Mail server hostname (dangling = potential mail interception)
# - NS: Nameserver delegation (dangling = subdomain takeover)
# - SRV: Service location hostname
DANGLING_RISK_TYPES = {"CNAME", "MX", "NS", "SRV"}

# Risk descriptions for each record type
RISK_DESCRIPTIONS = {
    "CNAME": "subdomain takeover risk",
    "MX": "potential mail interception risk",
    "NS": "subdomain delegation takeover risk",
    "SRV": "service discovery vulnerability",
}


class dns_record_cname_target_valid(Check):
    """Ensure that DNS records pointing to hostnames have valid, resolvable targets.

    Dangling DNS records that point to non-existent or unresolvable targets pose
    significant security risks. CNAME and NS records can lead to subdomain takeover,
    MX records can allow mail interception, and SRV records can expose service
    vulnerabilities. Attackers can claim orphaned target resources and serve
    malicious content, intercept email, or hijack services under your domain.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the dangling DNS record validation check.

        Iterates through all DNS records that point to hostnames (CNAME, MX, NS, SRV)
        and attempts to resolve their targets using DNS lookup. Records pointing to
        unresolvable targets are flagged as potential security risks.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if the
            target resolves successfully, or FAIL status if the target
            cannot be resolved (dangling record).
        """
        findings = []

        for record in dns_client.records:
            # Check record types that point to hostnames
            if record.type not in DANGLING_RISK_TYPES:
                continue

            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=record,
            )

            target = self._extract_target(record.type, record.content)
            is_valid = self._check_target_resolves(target)
            risk_desc = RISK_DESCRIPTIONS.get(record.type, "security risk")

            if is_valid:
                report.status = "PASS"
                report.status_extended = f"{record.type} record {record.name} points to valid target {target}."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"{record.type} record {record.name} points to potentially dangling "
                    f"target {target} - {risk_desc}."
                )
            findings.append(report)

        return findings

    def _extract_target(self, record_type: str, content: str) -> str:
        """Extract the target hostname from record content.

        Different record types have different content formats:
        - CNAME: hostname
        - MX: priority hostname (e.g., "10 mail.example.com")
        - NS: hostname
        - SRV: Cloudflare returns "weight port hostname" (e.g., "5 80 sip.example.com")
        """
        if record_type == "MX":
            # MX format: "priority hostname"
            parts = content.split(None, 1)
            return parts[1] if len(parts) > 1 else content
        elif record_type == "SRV":
            # SRV format from Cloudflare: "weight port hostname"
            parts = content.split()
            # Target is the last part (hostname)
            return parts[-1] if parts else content
        else:
            # CNAME and NS are just hostnames
            return content

    def _check_target_resolves(self, target: str) -> bool:
        """Check if target hostname resolves to a valid address."""
        # Remove trailing dot if present
        target = target.rstrip(".")

        try:
            # Attempt DNS resolution
            socket.getaddrinfo(target, None, socket.AF_UNSPEC)
            return True
        except socket.gaierror:
            # DNS resolution failed - potential dangling record
            return False
        except Exception:
            # On any other error, assume valid to avoid false positives
            return True
