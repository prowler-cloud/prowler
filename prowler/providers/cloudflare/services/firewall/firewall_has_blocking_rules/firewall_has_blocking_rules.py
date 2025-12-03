from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.firewall.firewall_client import (
    firewall_client,
)

BLOCKING_ACTIONS = {"block", "challenge", "js_challenge", "managed_challenge"}


class firewall_has_blocking_rules(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []

        for rule in firewall_client.rules:
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=rule,
                zone=rule.zone,
            )

            if rule.action in BLOCKING_ACTIONS:
                report.status = "PASS"
                report.status_extended = (
                    f"Firewall rule '{rule.name}' uses blocking action '{rule.action}'."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"Firewall rule '{rule.name}' uses non-blocking action '{rule.action}'."
            findings.append(report)

        return findings
