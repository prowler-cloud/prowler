from typing import List

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.dns.dns_client import dns_client


class dns_dnssec_enabled(Check):
    """Check if DNSSEC is enabled to prevent DNS spoofing"""

    def execute(self) -> List[CheckReportCloudflare]:
        findings = []

        for zone_id, dnssec_settings in dns_client.dnssec_settings.items():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=dnssec_settings,
                resource_name=dnssec_settings.zone_name,
                resource_id=zone_id,
                zone_name=dnssec_settings.zone_name,
            )

            if dnssec_settings.dnssec_enabled:
                report.status = "PASS"
                report.status_extended = f"Zone {dnssec_settings.zone_name} has DNSSEC enabled (status: {dnssec_settings.dnssec_status}), preventing DNS spoofing and ensuring data integrity."
            else:
                report.status = "FAIL"
                report.status_extended = f"Zone {dnssec_settings.zone_name} does not have DNSSEC enabled (status: {dnssec_settings.dnssec_status}). Enable DNSSEC to prevent DNS spoofing and ensure data integrity."

            findings.append(report)

        return findings
