from typing import List

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.ssl.ssl_client import ssl_client


class ssl_mode_full_strict(Check):
    """Check if SSL/TLS mode is set to Full (strict) for end-to-end encryption"""

    def execute(self) -> List[CheckReportCloudflare]:
        findings = []
        for zone_id, ssl_settings in ssl_client.ssl_settings.items():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=ssl_settings,
                resource_name=ssl_settings.zone_name,
                resource_id=zone_id,
                zone_name=ssl_settings.zone_name,
            )

            # SSL mode should be "full" or "strict" for end-to-end encryption
            if ssl_settings.ssl_mode in ["full", "strict"]:
                report.status = "PASS"
                report.status_extended = f"Zone {ssl_settings.zone_name} has SSL/TLS mode set to '{ssl_settings.ssl_mode}' ensuring end-to-end encryption."
            else:
                report.status = "FAIL"
                report.status_extended = f"Zone {ssl_settings.zone_name} has SSL/TLS mode set to '{ssl_settings.ssl_mode}'. Recommended: 'full' or 'strict' for end-to-end encryption with certificate validation."

            findings.append(report)

        return findings
