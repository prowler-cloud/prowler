from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_automatic_https_rewrites_enabled(Check):
    """Ensure that Automatic HTTPS Rewrites is enabled for Cloudflare zones.

    Automatic HTTPS Rewrites automatically rewrites insecure HTTP links to HTTPS,
    resolving mixed content issues and enhancing site security. This feature scans
    HTML responses and rewrites HTTP URLs to HTTPS for resources that are known to
    be available over a secure connection, preventing mixed content warnings.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the Automatic HTTPS Rewrites enabled check.

        Iterates through all Cloudflare zones and verifies that Automatic HTTPS
        Rewrites is enabled. This setting automatically fixes mixed content issues
        by rewriting HTTP links to HTTPS where possible.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if Automatic
            HTTPS Rewrites is enabled, or FAIL status if it is disabled for the zone.
        """
        findings = []
        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            automatic_https_rewrites = (
                zone.settings.automatic_https_rewrites or ""
            ).lower()
            if automatic_https_rewrites == "on":
                report.status = "PASS"
                report.status_extended = (
                    f"Automatic HTTPS Rewrites is enabled for zone {zone.name}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Automatic HTTPS Rewrites is not enabled for zone {zone.name}."
                )
            findings.append(report)
        return findings
