from typing import List

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.ssl.ssl_client import ssl_client


class ssl_opportunistic_encryption_enabled(Check):
    """Check if Opportunistic Encryption is enabled for HTTP/2 benefits"""

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

            if ssl_settings.opportunistic_encryption:
                report.status = "PASS"
                report.status_extended = f"Zone {ssl_settings.zone_name} has Opportunistic Encryption enabled, providing HTTP/2 benefits over encrypted connections."
            else:
                report.status = "FAIL"
                report.status_extended = f"Zone {ssl_settings.zone_name} does not have Opportunistic Encryption enabled. Enable it to provide HTTP/2 benefits over encrypted connections."

            findings.append(report)

        return findings
