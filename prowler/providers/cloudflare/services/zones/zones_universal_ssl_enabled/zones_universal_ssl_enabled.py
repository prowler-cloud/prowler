from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_universal_ssl_enabled(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for zone in zones_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            if zone.settings.universal_ssl_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Universal SSL is enabled for zone {zone.name}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Universal SSL is not enabled for zone {zone.name}."
                )
            findings.append(report)
        return findings
