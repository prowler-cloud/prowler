from typing import List

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.firewall.firewall_client import (
    firewall_client,
)


class firewall_waf_enabled(Check):
    """Check if Web Application Firewall (WAF) is enabled for Cloudflare zones

    This class verifies whether each Cloudflare zone has WAF enabled to protect
    against common web application attacks.
    """

    def execute(self) -> List[CheckReportCloudflare]:
        """Execute the Cloudflare WAF enabled check

        Iterates over all zones and checks if WAF is enabled.

        Returns:
            List[CheckReportCloudflare]: A list of reports for each zone
        """
        findings = []
        for zone_id, zone in firewall_client.zones.items():
            report = CheckReportCloudflare(metadata=self.metadata(), resource=zone)
            report.status = "FAIL"
            report.status_extended = f"Zone {zone.name} does not have WAF enabled."

            if zone.waf_enabled:
                report.status = "PASS"
                report.status_extended = f"Zone {zone.name} has WAF enabled."

            findings.append(report)

        return findings
