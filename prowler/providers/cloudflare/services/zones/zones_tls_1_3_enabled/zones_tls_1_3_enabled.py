from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_tls_1_3_enabled(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for zone in zones_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            tls_1_3 = (zone.settings.tls_1_3 or "").lower()
            if tls_1_3 in ["on", "zrt"]:
                report.status = "PASS"
                report.status_extended = f"TLS 1.3 is enabled for zone {zone.name}."
            else:
                report.status = "FAIL"
                report.status_extended = f"TLS 1.3 is not enabled for zone {zone.name}."
            findings.append(report)
        return findings
