from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.lib.read_errors import (
    ZONE_SETTINGS_READ,
    split_unreadable_zones,
)
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_ip_geolocation_enabled(Check):
    """Ensure that IP Geolocation is enabled for Cloudflare zones.

    IP Geolocation adds the CF-IPCountry header to all requests, containing the
    two-letter country code of the visitor's location. This enables geographic-based
    access controls, firewall rules, content customization, and analytics based on
    visitor location.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the IP Geolocation enabled check.

        Iterates through all Cloudflare zones and verifies that IP Geolocation
        is enabled. This feature adds geographic information to requests for
        enhanced security controls and analytics.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if IP
            Geolocation is enabled, or FAIL status if it is disabled for the zone.
        """
        findings, zones = split_unreadable_zones(
            self,
            zone_client.zones.values(),
            read_error=lambda zone: zone.read_errors.get("ip_geolocation"),
            requirement="the IP Geolocation setting",
            permission=ZONE_SETTINGS_READ,
        )
        for zone in zones:
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            ip_geolocation = (zone.settings.ip_geolocation or "").lower()

            if ip_geolocation == "on":
                report.status = "PASS"
                report.status_extended = (
                    f"IP Geolocation is enabled for zone {zone.name}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"IP Geolocation is not enabled for zone {zone.name}."
                )
            findings.append(report)
        return findings
