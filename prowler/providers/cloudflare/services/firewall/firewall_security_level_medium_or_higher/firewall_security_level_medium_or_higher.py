from typing import List

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.firewall.firewall_client import (
    firewall_client,
)


class firewall_security_level_medium_or_higher(Check):
    """Check if Security Level is set to Medium or higher"""

    def execute(self) -> List[CheckReportCloudflare]:
        findings = []
        # Security levels in order: off, essentially_off, low, medium, high, under_attack
        acceptable_levels = ["medium", "high", "under_attack"]

        for zone_id, security_settings in firewall_client.security_settings.items():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=security_settings,
                resource_name=security_settings.zone_name,
                resource_id=zone_id,
                zone_name=security_settings.zone_name,
            )

            if security_settings.security_level in acceptable_levels:
                report.status = "PASS"
                report.status_extended = f"Zone {security_settings.zone_name} has Security Level set to '{security_settings.security_level}', providing adequate protection."
            else:
                report.status = "FAIL"
                report.status_extended = f"Zone {security_settings.zone_name} has Security Level set to '{security_settings.security_level}'. Recommended: 'medium' or higher to balance protection with user accessibility."

            findings.append(report)

        return findings
