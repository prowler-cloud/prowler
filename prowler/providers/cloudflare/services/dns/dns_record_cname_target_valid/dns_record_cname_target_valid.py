import socket

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.dns.dns_client import dns_client


class dns_record_cname_target_valid(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []

        for record in dns_client.records:
            # Only check CNAME records
            if record.type != "CNAME":
                continue

            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=record,
                zone=record.zone,
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
