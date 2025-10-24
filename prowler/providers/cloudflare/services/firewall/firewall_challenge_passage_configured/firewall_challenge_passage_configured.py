from typing import List

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.firewall.firewall_client import (
    firewall_client,
)


class firewall_challenge_passage_configured(Check):
    """Check if Challenge Passage is configured appropriately"""

    def execute(self) -> List[CheckReportCloudflare]:
        findings = []
        # Recommended challenge TTL is 1 hour (3600 seconds) to balance security and user experience
        recommended_ttl = 3600

        for zone_id, security_settings in firewall_client.security_settings.items():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=security_settings,
                resource_name=security_settings.zone_name,
                resource_id=zone_id,
                zone_name=security_settings.zone_name,
            )

            if security_settings.challenge_ttl == recommended_ttl:
                report.status = "PASS"
                report.status_extended = f"Zone {security_settings.zone_name} has Challenge Passage set to {security_settings.challenge_ttl} seconds (recommended: {recommended_ttl}), balancing security with user experience."
            else:
                report.status = "FAIL"
                report.status_extended = f"Zone {security_settings.zone_name} has Challenge Passage set to {security_settings.challenge_ttl} seconds. Recommended: {recommended_ttl} seconds (1 hour) to reduce friction for verified visitors while maintaining security."

            findings.append(report)

        return findings
