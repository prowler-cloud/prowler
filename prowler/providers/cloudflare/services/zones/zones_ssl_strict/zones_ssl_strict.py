from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_ssl_strict(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for zone in zones_client.zones:
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            ssl_mode = (zone.settings.ssl_encryption_mode or "").lower()
            if ssl_mode in ["strict", "full_strict"]:
                report.status = "PASS"
                report.status_extended = f"SSL/TLS encryption mode is set to '{ssl_mode}' for zone {zone.name}."
            else:
                report.status = "FAIL"
                report.status_extended = f"SSL/TLS encryption mode is set to '{ssl_mode}' for zone {zone.name}."
            findings.append(report)
        return findings
