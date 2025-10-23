from typing import List

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.firewall.firewall_client import (
    firewall_client,
)


class firewall_browser_integrity_check_enabled(Check):
    """Check if Browser Integrity Check is enabled to filter malicious traffic"""

    def execute(self) -> List[CheckReportCloudflare]:
        findings = []

        for zone_id, security_settings in firewall_client.security_settings.items():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=security_settings,
                resource_name=security_settings.zone_name,
                resource_id=zone_id,
                zone_name=security_settings.zone_name,
            )

            if security_settings.browser_integrity_check:
                report.status = "PASS"
                report.status_extended = f"Zone {security_settings.zone_name} has Browser Integrity Check enabled, filtering malicious traffic based on HTTP header anomalies."
            else:
                report.status = "FAIL"
                report.status_extended = f"Zone {security_settings.zone_name} does not have Browser Integrity Check enabled. Enable it to filter malicious traffic based on HTTP header anomalies."

            findings.append(report)

        return findings
