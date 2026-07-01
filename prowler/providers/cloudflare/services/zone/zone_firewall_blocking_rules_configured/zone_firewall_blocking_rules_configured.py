from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client

BLOCKING_ACTIONS = {"block", "challenge", "js_challenge", "managed_challenge"}


class zone_firewall_blocking_rules_configured(Check):
    """Ensure that firewall rules with blocking actions are configured for Cloudflare zones.

    Firewall rules should use blocking actions (block, challenge, js_challenge,
    managed_challenge) to actively protect against threats rather than only logging
    traffic. Without blocking actions, malicious requests can reach the origin server
    and potentially compromise the application's security.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the firewall blocking rules configured check.

        Iterates through all Cloudflare zones and verifies that at least one
        firewall rule exists with a blocking action. Blocking actions include
        block, challenge, js_challenge, and managed_challenge.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if blocking
            rules are configured, or FAIL status if no blocking rules exist.
        """
        findings = []

        for zone in zone_client.zones.values():
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
