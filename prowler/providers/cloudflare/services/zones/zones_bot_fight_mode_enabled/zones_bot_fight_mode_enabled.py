from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_bot_fight_mode_enabled(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for zone in zones_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            browser_check = (zone.settings.browser_check or "").lower()
            if browser_check == "on":
                report.status = "PASS"
                report.status_extended = f"Bot Fight Mode (Browser Integrity Check) is enabled for zone {zone.name}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Bot Fight Mode (Browser Integrity Check) is not enabled for zone {zone.name}."
            findings.append(report)
        return findings
