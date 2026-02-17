from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_tls_1_3_enabled(Check):
    """Ensure that TLS 1.3 is enabled for Cloudflare zones.

    TLS 1.3 provides improved security through simplified cipher suites and
    faster handshakes with zero round-trip time (0-RTT) resumption. It removes
    outdated cryptographic algorithms, reduces handshake latency, and provides
    better forward secrecy compared to previous TLS versions.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the TLS 1.3 enabled check.

        Iterates through all Cloudflare zones and verifies that TLS 1.3 is
        enabled. The check accepts both "on" (standard TLS 1.3) and "zrt"
        (TLS 1.3 with 0-RTT) as valid enabled states.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if TLS 1.3
            is enabled, or FAIL status if it is disabled for the zone.
        """
        findings = []
        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            tls_1_3 = (zone.settings.tls_1_3 or "").lower()
            if tls_1_3 in ["on", "zrt"]:
                report.status = "PASS"
                report.status_extended = f"TLS 1.3 is enabled for zone {zone.name}."
            else:
                report.status = "FAIL"
                report.status_extended = f"TLS 1.3 is not enabled for zone {zone.name}."
            findings.append(report)
        return findings
