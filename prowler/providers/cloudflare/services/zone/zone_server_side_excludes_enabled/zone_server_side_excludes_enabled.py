from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_server_side_excludes_enabled(Check):
    """Ensure that Server Side Excludes is enabled for Cloudflare zones.

    Server Side Excludes (SSE) is part of Cloudflare's Scrape Shield suite that
    automatically hides content wrapped in SSE tags from visitors identified as
    suspicious bots or crawlers. This protects sensitive information like email
    addresses and phone numbers from being scraped.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the Server Side Excludes enabled check.

        Iterates through all Cloudflare zones and verifies that Server Side
        Excludes is enabled. This feature helps protect sensitive content from
        being scraped by malicious bots.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if Server
            Side Excludes is enabled, or FAIL status if it is disabled for the zone.
        """
        findings = []
        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            server_side_exclude = (zone.settings.server_side_exclude or "").lower()
            if server_side_exclude == "on":
                report.status = "PASS"
                report.status_extended = (
                    f"Server Side Excludes is enabled for zone {zone.name}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Server Side Excludes is not enabled for zone {zone.name}."
                )
            findings.append(report)
        return findings
