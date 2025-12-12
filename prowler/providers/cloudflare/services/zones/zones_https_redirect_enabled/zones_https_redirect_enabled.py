from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_https_redirect_enabled(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for zone in zones_client.zones:
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            if zone.settings.always_use_https == "on":
                report.status = "PASS"
                report.status_extended = (
                    f"Always Use HTTPS is enabled for zone {zone.name}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Always Use HTTPS is not enabled for zone {zone.name}."
                )
            findings.append(report)
        return findings
