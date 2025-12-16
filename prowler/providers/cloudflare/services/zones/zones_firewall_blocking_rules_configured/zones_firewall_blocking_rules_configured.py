from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client

BLOCKING_ACTIONS = {"block", "challenge", "js_challenge", "managed_challenge"}


class zones_firewall_blocking_rules_configured(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []

        for zone in zones_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )

            # Find blocking rules for this zone
            blocking_rules = [
                rule for rule in zone.firewall_rules if rule.action in BLOCKING_ACTIONS
            ]

            if blocking_rules:
                report.status = "PASS"
                report.status_extended = (
                    f"Zone {zone.name} has firewall rules with blocking actions "
                    f"({len(blocking_rules)} rule(s))."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Zone {zone.name} has no firewall rules with blocking actions."
                )
            findings.append(report)

        return findings
