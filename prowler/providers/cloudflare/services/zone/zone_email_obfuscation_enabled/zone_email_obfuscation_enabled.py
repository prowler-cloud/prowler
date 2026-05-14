from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_email_obfuscation_enabled(Check):
    """Ensure that Email Obfuscation is enabled for Cloudflare zones.

    Email Obfuscation is part of Cloudflare's Scrape Shield suite that protects
    email addresses displayed on websites from automated harvesting by bots and
    spammers. It encrypts email addresses in the HTML source while keeping them
    visible to human visitors, reducing spam and protecting user privacy.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the Email Obfuscation enabled check.

        Iterates through all Cloudflare zones and verifies that Email Obfuscation
        is enabled. This feature helps prevent email harvesting by obfuscating
        email addresses in the page source.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if Email
            Obfuscation is enabled, or FAIL status if it is disabled for the zone.
        """
        findings = []
        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            email_obfuscation = (zone.settings.email_obfuscation or "").lower()
            if email_obfuscation == "on":
                report.status = "PASS"
                report.status_extended = (
                    f"Email Obfuscation is enabled for zone {zone.name}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Email Obfuscation is not enabled for zone {zone.name}."
                )
            findings.append(report)
        return findings
