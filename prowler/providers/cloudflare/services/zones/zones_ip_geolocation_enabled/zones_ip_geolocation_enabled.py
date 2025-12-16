from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_ip_geolocation_enabled(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for zone in zones_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            ip_geolocation = (zone.settings.ip_geolocation or "").lower()

            if ip_geolocation == "on":
                report.status = "PASS"
                report.status_extended = (
                    f"IP Geolocation is enabled for zone {zone.name}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"IP Geolocation is not enabled for zone {zone.name}."
                )
            findings.append(report)
        return findings
