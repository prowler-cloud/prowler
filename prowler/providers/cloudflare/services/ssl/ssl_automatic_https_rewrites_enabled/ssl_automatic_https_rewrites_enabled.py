from typing import List

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.ssl.ssl_client import ssl_client


class ssl_automatic_https_rewrites_enabled(Check):
    """Check if Automatic HTTPS Rewrites is enabled to resolve mixed content issues"""

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

            if ssl_settings.automatic_https_rewrites:
                report.status = "PASS"
                report.status_extended = f"Zone {ssl_settings.zone_name} has Automatic HTTPS Rewrites enabled, resolving mixed content issues and enhancing site security."
            else:
                report.status = "FAIL"
                report.status_extended = f"Zone {ssl_settings.zone_name} does not have Automatic HTTPS Rewrites enabled. Enable it to automatically rewrite HTTP links to HTTPS and prevent mixed content warnings."

            findings.append(report)

        return findings
