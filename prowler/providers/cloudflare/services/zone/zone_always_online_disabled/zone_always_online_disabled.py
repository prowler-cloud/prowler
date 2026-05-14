from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_always_online_disabled(Check):
    """Ensure that Always Online is disabled for Cloudflare zones.

    Always Online serves stale cached content when the origin server is unavailable.
    While this maintains availability, it can expose outdated or potentially sensitive
    information. For security-sensitive applications, it is recommended to disable
    this feature to ensure users always receive current, accurate content or an
    appropriate error message when the origin is down.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the Always Online disabled check.

        Iterates through all Cloudflare zones and verifies that Always Online
        is disabled. When enabled, this feature may serve stale cached content
        that could contain outdated or sensitive information.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if Always
            Online is disabled, or FAIL status if it is enabled for the zone.
        """
        findings = []
        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            always_online = (zone.settings.always_online or "").lower()

            if always_online == "off":
                report.status = "PASS"
                report.status_extended = (
                    f"Always Online is disabled for zone {zone.name}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Always Online is enabled for zone {zone.name}."
                )
            findings.append(report)
        return findings
