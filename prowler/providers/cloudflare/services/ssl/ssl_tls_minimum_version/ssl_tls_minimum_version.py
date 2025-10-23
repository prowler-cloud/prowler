from typing import List

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.ssl.ssl_client import ssl_client


class ssl_tls_minimum_version(Check):
    """Check if Cloudflare zones have minimum TLS version set to 1.2 or higher

    This class verifies that each Cloudflare zone enforces a minimum TLS version
    of 1.2 or higher to ensure secure connections.
    """

    def execute(self) -> List[CheckReportCloudflare]:
        """Execute the Cloudflare minimum TLS version check

        Iterates over all SSL settings and checks the minimum TLS version.

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
            report.status_extended = f"Zone {ssl_settings.zone_name} has minimum TLS version set to {ssl_settings.min_tls_version}, which is below the recommended 1.2."

            # Check if minimum TLS version is 1.2 or higher
            if ssl_settings.min_tls_version in ["1.2", "1.3"]:
                report.status = "PASS"
                report.status_extended = f"Zone {ssl_settings.zone_name} has minimum TLS version set to {ssl_settings.min_tls_version}."

            findings.append(report)

        return findings
