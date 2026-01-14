from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_bot_fight_mode_enabled(Check):
    """Ensure that Bot Fight Mode is enabled for Cloudflare zones.

    Bot Fight Mode (Browser Integrity Check) detects and mitigates automated bot
    traffic by analyzing browser characteristics and behavior patterns. It challenges
    requests that appear to come from bots or clients with missing/invalid browser
    headers, protecting against scraping, spam, and automated attacks.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the Bot Fight Mode enabled check.

        Iterates through all Cloudflare zones and verifies that Bot Fight Mode
        (Browser Integrity Check) is enabled. This feature helps identify and
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
            browser_check = (zone.settings.browser_check or "").lower()
            if browser_check == "on":
                report.status = "PASS"
                report.status_extended = f"Bot Fight Mode (Browser Integrity Check) is enabled for zone {zone.name}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Bot Fight Mode (Browser Integrity Check) is not enabled for zone {zone.name}."
            findings.append(report)
        return findings
