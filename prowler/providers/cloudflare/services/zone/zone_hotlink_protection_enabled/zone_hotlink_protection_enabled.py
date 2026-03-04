from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_hotlink_protection_enabled(Check):
    """Ensure that Hotlink Protection is enabled for Cloudflare zones.

    Hotlink Protection is part of Cloudflare's Scrape Shield suite that prevents
    other websites from directly linking to images, videos, and other media files,
    which consumes bandwidth without authorization. It blocks requests where the
    HTTP referer does not match your domain.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the Hotlink Protection enabled check.

        Iterates through all Cloudflare zones and verifies that Hotlink Protection
        is enabled. This feature prevents bandwidth theft by blocking unauthorized
        embedding of your media on external sites.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if Hotlink
            Protection is enabled, or FAIL status if it is disabled for the zone.
        """
        findings = []
        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            hotlink_protection = (zone.settings.hotlink_protection or "").lower()
            if hotlink_protection == "on":
                report.status = "PASS"
                report.status_extended = (
                    f"Hotlink Protection is enabled for zone {zone.name}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Hotlink Protection is not enabled for zone {zone.name}."
                )
            findings.append(report)
        return findings
