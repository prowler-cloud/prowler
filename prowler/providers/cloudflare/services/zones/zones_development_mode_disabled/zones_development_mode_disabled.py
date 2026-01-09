from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_development_mode_disabled(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for zone in zones_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            dev_mode = (zone.settings.development_mode or "").lower()
            if dev_mode == "off" or not dev_mode:
                report.status = "PASS"
                report.status_extended = (
                    f"Development mode is disabled for zone {zone.name}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Development mode is enabled for zone {zone.name}. "
                    "This bypasses Cloudflare caching and should be disabled in production."
                )
            findings.append(report)
        return findings
