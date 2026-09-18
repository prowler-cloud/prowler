from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_min_tls_version_secure(Check):
    """Ensure that minimum TLS version is set to 1.2 or higher for Cloudflare zones.

    TLS 1.0 and 1.1 have known vulnerabilities (BEAST, POODLE) and are deprecated.
    Setting the minimum TLS version to 1.2 or higher ensures that only secure
    cipher suites are used for encrypted connections, protecting against
    downgrade attacks and known cryptographic weaknesses.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the minimum TLS version check.

        Iterates through all Cloudflare zones and verifies that the minimum
        TLS version is configured to 1.2 or higher. The check parses the
        min_tls_version setting as a float for comparison, defaulting to 0
        if the value cannot be parsed.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if the
            minimum TLS version is 1.2 or higher, or FAIL status if older
            TLS versions (1.0, 1.1) are still allowed.
        """
        findings = []

        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            current_version = zone.settings.min_tls_version or "0"
            try:
                current = float(current_version)
            except ValueError:
                current = 0

            if current >= 1.2:
                report.status = "PASS"
                report.status_extended = f"Minimum TLS version for zone {zone.name} is set to {current_version}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Minimum TLS version for zone {zone.name} is {current_version}, below the recommended 1.2."
            findings.append(report)
        return findings
