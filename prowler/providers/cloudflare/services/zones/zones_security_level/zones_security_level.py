from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_security_level(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        acceptable_levels = ["medium", "high", "under_attack"]

        for zone in zones_client.zones:
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            security_level = (zone.settings.security_level or "").lower()
            if security_level in acceptable_levels:
                report.status = "PASS"
                report.status_extended = (
                    f"Security level is set to '{security_level}' for zone {zone.name}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Security level is set to '{security_level}' for zone {zone.name}."
                )
            findings.append(report)
        return findings
