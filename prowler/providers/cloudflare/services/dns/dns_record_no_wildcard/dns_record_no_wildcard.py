from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.dns.dns_client import dns_client


class dns_record_no_wildcard(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []

        for record in dns_client.records:
            # Only check A, AAAA, and CNAME records for wildcards
            if record.type not in ("A", "AAAA", "CNAME"):
                continue

            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=record,
            )

            # Check if record name starts with wildcard
            is_wildcard = record.name.startswith("*.")

            if not is_wildcard:
                report.status = "PASS"
                report.status_extended = f"DNS record '{record.name}' ({record.type}) is not a wildcard record."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"DNS record '{record.name}' ({record.type}) is a wildcard record - "
                    f"may expose unintended services."
                )
            findings.append(report)

        return findings
