from typing import List

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.ssl.ssl_client import ssl_client


class ssl_hsts_enabled(Check):
    """Check if HSTS (HTTP Strict Transport Security) is enabled with recommended max-age"""

    def execute(self) -> List[CheckReportCloudflare]:
        findings = []
        # Recommended minimum max-age is 6 months (15768000 seconds)
        recommended_max_age = 15768000

        for zone_id, ssl_settings in ssl_client.ssl_settings.items():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=ssl_settings,
                resource_name=ssl_settings.zone_name,
                resource_id=zone_id,
                zone_name=ssl_settings.zone_name,
            )

            if ssl_settings.hsts_enabled:
                if ssl_settings.hsts_max_age >= recommended_max_age:
                    report.status = "PASS"
                    report.status_extended = f"Zone {ssl_settings.zone_name} has HSTS enabled with max-age of {ssl_settings.hsts_max_age} seconds (>= {recommended_max_age} recommended)."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Zone {ssl_settings.zone_name} has HSTS enabled but max-age is {ssl_settings.hsts_max_age} seconds (< {recommended_max_age} recommended). Increase max-age for better security."
            else:
                report.status = "FAIL"
                report.status_extended = f"Zone {ssl_settings.zone_name} does not have HSTS enabled. Enable HSTS to prevent SSL stripping and man-in-the-middle attacks."

            findings.append(report)

        return findings
