from typing import List

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.ssl.ssl_client import ssl_client


class ssl_always_use_https(Check):
    """Check if Cloudflare zones have 'Always Use HTTPS' enabled

    This class verifies that each Cloudflare zone has 'Always Use HTTPS' enabled
    to automatically redirect HTTP requests to HTTPS.
    """

    def execute(self) -> List[CheckReportCloudflare]:
        """Execute the Cloudflare Always Use HTTPS check

        Iterates over all SSL settings and checks if Always Use HTTPS is enabled.

        Returns:
            List[CheckReportCloudflare]: A list of reports for each zone
        """
        findings = []
        for zone_id, ssl_settings in ssl_client.ssl_settings.items():
            zone = ssl_client.zones.get(zone_id)
            if not zone:
                continue

            report = CheckReportCloudflare(
                metadata=self.metadata(), resource=ssl_settings
            )
            report.status = "FAIL"
            report.status_extended = f"Zone {ssl_settings.zone_name} does not have 'Always Use HTTPS' enabled."

            if ssl_settings.always_use_https:
                report.status = "PASS"
                report.status_extended = (
                    f"Zone {ssl_settings.zone_name} has 'Always Use HTTPS' enabled."
                )

            findings.append(report)

        return findings
