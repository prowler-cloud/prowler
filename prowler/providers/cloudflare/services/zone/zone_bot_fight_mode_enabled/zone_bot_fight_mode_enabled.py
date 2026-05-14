from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_bot_fight_mode_enabled(Check):
    """Ensure that Bot Fight Mode is enabled for Cloudflare zones.

    Bot Fight Mode is a free Cloudflare feature that detects and mitigates automated
    bot traffic. It uses JavaScript challenges and behavioral analysis to identify
    bots and block malicious automated traffic, protecting against scraping, spam,
    credential stuffing, and other automated attacks.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the Bot Fight Mode enabled check.

        Iterates through all Cloudflare zones and verifies that Bot Fight Mode
        is enabled via the Bot Management API. This feature helps identify and
        block malicious bot traffic.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if Bot Fight
            Mode is enabled, or FAIL status if it is disabled for the zone.
        """
        findings = []
        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            if zone.settings.bot_fight_mode_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Bot Fight Mode is enabled for zone {zone.name}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bot Fight Mode is not enabled for zone {zone.name}."
                )
            findings.append(report)
        return findings
