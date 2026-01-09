from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_server_side_excludes_enabled(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for zone in zones_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            server_side_exclude = (zone.settings.server_side_exclude or "").lower()
            if server_side_exclude == "on":
                report.status = "PASS"
                report.status_extended = (
                    f"Server Side Excludes is enabled for zone {zone.name}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Server Side Excludes is not enabled for zone {zone.name}."
                )
            findings.append(report)
        return findings
