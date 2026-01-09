from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_email_obfuscation_enabled(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for zone in zones_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            email_obfuscation = (zone.settings.email_obfuscation or "").lower()
            if email_obfuscation == "on":
                report.status = "PASS"
                report.status_extended = (
                    f"Email Obfuscation is enabled for zone {zone.name}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Email Obfuscation is not enabled for zone {zone.name}."
                )
            findings.append(report)
        return findings
