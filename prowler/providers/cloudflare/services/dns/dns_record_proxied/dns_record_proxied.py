from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.dns.dns_client import dns_client

PROXYABLE_TYPES = {"A", "AAAA", "CNAME"}


class dns_record_proxied(Check):
    def execute(self) -> list[CheckReportCloudflare]:
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
                report.status_extended = f"DNS record '{record.name}' ({record.type}) is proxied through Cloudflare."
            else:
                report.status = "FAIL"
                report.status_extended = f"DNS record '{record.name}' ({record.type}) is not proxied through Cloudflare."
            findings.append(report)

        return findings
