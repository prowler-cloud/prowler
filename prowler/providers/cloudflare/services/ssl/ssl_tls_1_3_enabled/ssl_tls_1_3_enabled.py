from typing import List

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.ssl.ssl_client import ssl_client


class ssl_tls_1_3_enabled(Check):
    """Check if TLS 1.3 is enabled for enhanced security and performance"""

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

            if ssl_settings.tls_1_3_enabled:
                report.status = "PASS"
                report.status_extended = f"Zone {ssl_settings.zone_name} has TLS 1.3 enabled, providing enhanced security and reduced connection time."
            else:
                report.status = "FAIL"
                report.status_extended = f"Zone {ssl_settings.zone_name} does not have TLS 1.3 enabled. Enable TLS 1.3 for improved security and performance."

            findings.append(report)

        return findings
