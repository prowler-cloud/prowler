from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_always_online_disabled(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for zone in zones_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            always_online = (zone.settings.always_online or "").lower()

            if always_online == "off":
                report.status = "PASS"
                report.status_extended = (
                    f"Always Online is disabled for zone {zone.name}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Always Online is enabled for zone {zone.name}."
                )
            findings.append(report)
        return findings
