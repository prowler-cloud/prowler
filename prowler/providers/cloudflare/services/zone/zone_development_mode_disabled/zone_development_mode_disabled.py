from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_development_mode_disabled(Check):
    """Ensure that Development Mode is disabled for production Cloudflare zones.

    Development Mode temporarily bypasses Cloudflare's caching and performance
    optimizations, serving content directly from the origin server. While useful
    for testing changes, it should be disabled in production to maintain caching,
    security features, and performance optimizations.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the Development Mode disabled check.

        Iterates through all Cloudflare zones and verifies that Development Mode
        is disabled. When enabled, this mode bypasses caching and can impact
        performance and security.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if Development
            Mode is disabled, or FAIL status if it is enabled for the zone.
        """
        findings = []
        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            dev_mode = (zone.settings.development_mode or "").lower()
            if dev_mode == "off" or not dev_mode:
                report.status = "PASS"
                report.status_extended = (
                    f"Development mode is disabled for zone {zone.name}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Development mode is enabled for zone {zone.name}."
                )
            findings.append(report)
        return findings
