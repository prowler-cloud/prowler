from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client
from prowler.providers.cloudflare.services.zone.zone_rules_expressions import (
    matches_all_traffic,
)


class zone_firewall_no_skip_all_traffic_rules(Check):
    """Ensure that no firewall rule skips security features for all traffic.

    A ``skip`` rule whose expression matches every request (for example ``true``)
    turns off the remaining custom rules, managed WAF rulesets, rate limiting or
    other security products for the whole zone, while the zone still reports WAF
    as enabled. Such rules are often left behind after debugging.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Look for enabled skip rules that match all traffic in every zone.

        Returns:
            One finding per zone: FAIL when an enabled skip rule matches every
            request, MANUAL when the zone's firewall rules could not be retrieved,
            PASS otherwise.
        """
        findings = []
        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(metadata=self.metadata(), resource=zone)
            bypass_rules = [
                rule
                for rule in zone.firewall_rules
                if rule.enabled
                and (rule.action or "").lower() == "skip"
                and matches_all_traffic(rule.expression)
            ]
            if bypass_rules:
                names = ", ".join(
                    f"{rule.description or rule.id} ({rule.phase}"
                    + (
                        f", skips {', '.join(rule.skip_targets)}"
                        if rule.skip_targets
                        else ""
                    )
                    + ")"
                    for rule in bypass_rules
                )
                report.status = "FAIL"
                report.status_extended = (
                    f"Zone {zone.name} has firewall skip rules that match all traffic "
                    f"and bypass security features: {names}."
                )
            elif zone.id in zone_client.firewall_rules_failed_zones:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Cannot evaluate firewall skip rules for zone {zone.name}: its "
                    "rulesets could not be retrieved. Verify that the scanning token "
                    "has the Zone WAF Read permission."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"Zone {zone.name} has no firewall skip rules that match all traffic."
            findings.append(report)
        return findings
