from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_hsts_enabled(Check):
    """Ensure that HSTS is enabled with secure settings for Cloudflare zones.

    HTTP Strict Transport Security (HSTS) forces browsers to only connect via
    HTTPS, preventing protocol downgrade attacks and cookie hijacking. This check
    verifies that HSTS is enabled with a minimum max-age of 6 months (15768000
    seconds) and includes subdomains for complete protection.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the HSTS enabled check.

        Iterates through all Cloudflare zones and validates HSTS configuration
        against security best practices. The check verifies three conditions:
        1. HSTS is enabled for the zone
        2. The includeSubdomains directive is set to protect all subdomains
        3. The max-age is at least 6 months (15768000 seconds)

        Returns:
            A list of CheckReportCloudflare objects with PASS status if all
            HSTS requirements are met, or FAIL status if HSTS is disabled,
            missing subdomain inclusion, or has insufficient max-age.
        """
        findings = []
        # Recommended minimum max-age is 6 months (15768000 seconds)
        recommended_max_age = 15768000

        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            hsts = zone.settings.strict_transport_security
            if hsts.enabled:
                if not hsts.include_subdomains:
                    report.status = "FAIL"
                    report.status_extended = f"HSTS is enabled for zone {zone.name} but does not include subdomains."
                elif hsts.max_age < recommended_max_age:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"HSTS is enabled for zone {zone.name} but max-age is "
                        f"{hsts.max_age} seconds (recommended: 6 months)."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"HSTS is enabled for zone {zone.name} with max-age of "
                        f"{hsts.max_age} seconds and includes subdomains."
                    )
            else:
                report.status = "FAIL"
                report.status_extended = f"HSTS is not enabled for zone {zone.name}."
            findings.append(report)
        return findings
