from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.firewall.firewall_client import (
    firewall_client,
)


class firewall_rate_limiting_configured(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []

        for rule in firewall_client.rules:
            # Only evaluate rate limit phase rules
            if rule.phase != "http_ratelimit":
                continue

            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=rule,
                zone=rule.zone,
            )

            if rule.enabled:
                report.status = "PASS"
                report.status_extended = f"Rate limiting rule '{rule.name}' is enabled."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Rate limiting rule '{rule.name}' is disabled."
                )
            findings.append(report)

        return findings
