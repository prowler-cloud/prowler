from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.firewall.firewall_client import (
    firewall_client,
)
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_rate_limiting_enabled(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []

        for zone in zones_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )

            # Find rate limiting rules for this zone
            rate_limit_rules = [
                rule
                for rule in firewall_client.rules
                if rule.zone_id == zone.id
                and rule.phase == "http_ratelimit"
                and rule.enabled
            ]

            if rate_limit_rules:
                report.status = "PASS"
                report.status_extended = (
                    f"Rate limiting is configured for zone {zone.name} "
                    f"({len(rate_limit_rules)} rule(s))."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"No rate limiting rules configured for zone {zone.name}."
                )
            findings.append(report)

        return findings
