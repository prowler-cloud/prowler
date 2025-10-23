from typing import List

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.ssl.ssl_client import ssl_client


class ssl_hsts_include_subdomains(Check):
    """Check if HSTS includes subdomains for comprehensive protection"""

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

            if ssl_settings.hsts_enabled and ssl_settings.hsts_include_subdomains:
                report.status = "PASS"
                report.status_extended = f"Zone {ssl_settings.zone_name} has HSTS enabled with includeSubDomains directive, protecting all subdomains."
            elif ssl_settings.hsts_enabled and not ssl_settings.hsts_include_subdomains:
                report.status = "FAIL"
                report.status_extended = f"Zone {ssl_settings.zone_name} has HSTS enabled but does not include subdomains. Enable includeSubDomains to protect all subdomains."
            else:
                report.status = "FAIL"
                report.status_extended = f"Zone {ssl_settings.zone_name} does not have HSTS enabled. Enable HSTS with includeSubDomains directive."

            findings.append(report)

        return findings
