from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_ssl_strict(Check):
    """Ensure that SSL/TLS encryption mode is set to Full (Strict) for Cloudflare zones.

    The SSL/TLS encryption mode determines how Cloudflare connects to the origin
    server. In 'strict' mode, Cloudflare validates the origin
    server's SSL certificate, ensuring end-to-end encryption with certificate
    verification. Lower modes (off, flexible, full) are vulnerable to
    man-in-the-middle attacks between Cloudflare and the origin.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the SSL strict mode check.

        Iterates through all Cloudflare zones and verifies that the SSL/TLS
        encryption mode is set to 'strict'. This mode
        requires a valid SSL certificate on the origin server and provides
        full end-to-end encryption with certificate validation.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if
            SSL mode is 'strict', or FAIL status if using
            less secure modes like 'off', 'flexible', or 'full'.
        """
        findings = []
        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            ssl_mode = (zone.settings.ssl_encryption_mode or "").lower()
            if ssl_mode == "strict":
                report.status = "PASS"
                report.status_extended = f"SSL/TLS encryption mode is set to Full (Strict) for zone {zone.name}."
            else:
                report.status = "FAIL"
                report.status_extended = f"SSL/TLS encryption mode is set to {ssl_mode.capitalize()} for zone {zone.name}, which is not Full (Strict)."
            findings.append(report)
        return findings
