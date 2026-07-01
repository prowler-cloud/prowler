from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_browser_integrity_check_enabled(Check):
    """Ensure that Browser Integrity Check is enabled for Cloudflare zones.

    Browser Integrity Check analyzes HTTP headers to identify requests from
    bots or clients with missing/invalid browser signatures. It challenges
    suspicious requests that don't have valid browser characteristics,
    protecting against basic automated attacks and malformed requests.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the Browser Integrity Check enabled check.

        Iterates through all Cloudflare zones and verifies that Browser
        Integrity Check is enabled. This feature validates browser headers
        to filter out basic bot traffic.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if Browser
            Integrity Check is enabled, or FAIL status if it is disabled.
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
                report.status_extended = (
                    f"Browser Integrity Check is enabled for zone {zone.name}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Browser Integrity Check is not enabled for zone {zone.name}."
                )
            findings.append(report)
        return findings
