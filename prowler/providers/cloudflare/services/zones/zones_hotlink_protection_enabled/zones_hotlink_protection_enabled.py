from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_hotlink_protection_enabled(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for zone in zones_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            hotlink_protection = (zone.settings.hotlink_protection or "").lower()
            if hotlink_protection == "on":
                report.status = "PASS"
                report.status_extended = (
                    f"Hotlink Protection is enabled for zone {zone.name}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Hotlink Protection is not enabled for zone {zone.name}."
                )
            findings.append(report)
        return findings
