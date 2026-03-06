from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_waf_enabled(Check):
    """Ensure that WAF is enabled for Cloudflare zones.

    The Web Application Firewall (WAF) protects against common web vulnerabilities
    including SQL injection, cross-site scripting (XSS), and other OWASP Top 10
    threats. When enabled, it inspects HTTP requests and blocks malicious traffic
    before it reaches the origin server.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the WAF enabled check.

        Iterates through all Cloudflare zones and verifies that the Web Application
        Firewall is enabled. The WAF provides essential protection against common
        web application attacks.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if WAF is
            enabled, or FAIL status if it is disabled for the zone.
        """
        findings = []
        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            waf_setting = (zone.settings.waf or "").lower()

            if waf_setting == "on":
                report.status = "PASS"
                report.status_extended = f"WAF is enabled for zone {zone.name}."
            else:
                report.status = "FAIL"
                report.status_extended = f"WAF is not enabled for zone {zone.name}."
            findings.append(report)
        return findings
