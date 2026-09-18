from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.lib.read_errors import (
    ZONE_SETTINGS_READ,
    split_unreadable_zones,
)
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_https_redirect_enabled(Check):
    """Ensure that Always Use HTTPS redirect is enabled for Cloudflare zones.

    The Always Use HTTPS setting automatically redirects all HTTP requests to
    HTTPS, ensuring that all traffic to the zone is encrypted. This prevents
    man-in-the-middle attacks and protects sensitive data transmitted between
    clients and the origin server.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the HTTPS redirect enabled check.

        Iterates through all Cloudflare zones and verifies that the
        always_use_https setting is turned on. When enabled, Cloudflare
        automatically redirects all HTTP requests to their HTTPS equivalents.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if
            Always Use HTTPS is enabled ('on'), or FAIL status if the
            setting is disabled for the zone.
        """
        findings, zones = split_unreadable_zones(
            self,
            zone_client.zones.values(),
            read_error=lambda zone: zone.read_errors.get("always_use_https"),
            requirement="the Always Use HTTPS setting",
            permission=ZONE_SETTINGS_READ,
        )
        for zone in zones:
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            if zone.settings.always_use_https == "on":
                report.status = "PASS"
                report.status_extended = (
                    f"Always Use HTTPS is enabled for zone {zone.name}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Always Use HTTPS is not enabled for zone {zone.name}."
                )
            findings.append(report)
        return findings
