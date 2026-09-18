from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_universal_ssl_enabled(Check):
    """Ensure that Universal SSL is enabled for Cloudflare zones.

    Universal SSL provides free SSL/TLS certificates for the domain and its
    subdomains, enabling secure HTTPS connections without requiring manual
    certificate management. This feature automatically provisions and renews
    certificates, ensuring continuous protection for web traffic.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the Universal SSL enabled check.

        Iterates through all Cloudflare zones and verifies that Universal SSL
        is enabled. Universal SSL provides automatic certificate provisioning
        and management for the zone and its subdomains.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if Universal
            SSL is enabled, or FAIL status if it is disabled for the zone.
        """
        findings = []
        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            if zone.settings.universal_ssl_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Universal SSL is enabled for zone {zone.name}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Universal SSL is not enabled for zone {zone.name}."
                )
            findings.append(report)
        return findings
