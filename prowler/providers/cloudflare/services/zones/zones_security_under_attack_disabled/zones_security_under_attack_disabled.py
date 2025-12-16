from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_security_under_attack_disabled(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []

        for zone in zones_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            security_level = (zone.settings.security_level or "").lower()

            if security_level == "under_attack":
                report.status = "FAIL"
                report.status_extended = (
                    f"Zone {zone.name} has Under Attack Mode enabled."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Zone {zone.name} does not have Under Attack Mode enabled."
                )
            findings.append(report)
        return findings
