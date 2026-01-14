import socket

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.dns.dns_client import dns_client


class dns_record_cname_target_valid(Check):
    """Ensure that CNAME records point to valid, resolvable targets.

    Dangling CNAME records that point to non-existent or unresolvable targets pose
    a significant security risk known as subdomain takeover. Attackers can claim
    the orphaned target resource and serve malicious content under your domain,
    potentially leading to phishing attacks, cookie theft, and reputation damage.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the CNAME target validation check.

        Iterates through all CNAME DNS records and attempts to resolve their
        targets using DNS lookup. Records pointing to unresolvable targets
        are flagged as potential subdomain takeover risks.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if the
            CNAME target resolves successfully, or FAIL status if the target
            cannot be resolved (dangling CNAME).
        """
        findings = []

        for record in dns_client.records:
            # Only check CNAME records
            if record.type != "CNAME":
                continue

            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=record,
            )

            target = record.content
            is_valid = self._check_cname_target(target)

            if is_valid:
                report.status = "PASS"
                report.status_extended = (
                    f"CNAME record '{record.name}' points to valid target '{target}'."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"CNAME record '{record.name}' points to potentially dangling target '{target}' - "
                    f"subdomain takeover risk."
                )
            findings.append(report)

        return findings

    def _check_cname_target(self, target: str) -> bool:
        """Check if CNAME target resolves to a valid address."""
        # Remove trailing dot if present
        target = target.rstrip(".")

        try:
            # Attempt DNS resolution
            socket.getaddrinfo(target, None, socket.AF_UNSPEC)
            return True
        except socket.gaierror:
            # DNS resolution failed - potential dangling CNAME
            return False
        except Exception:
            # On any other error, assume valid to avoid false positives
            return True
