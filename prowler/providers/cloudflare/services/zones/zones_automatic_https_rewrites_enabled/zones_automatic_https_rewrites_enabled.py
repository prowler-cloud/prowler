from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_automatic_https_rewrites_enabled(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for zone in zones_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            automatic_https_rewrites = (
                zone.settings.automatic_https_rewrites or ""
            ).lower()
            if automatic_https_rewrites == "on":
                report.status = "PASS"
                report.status_extended = (
                    f"Automatic HTTPS Rewrites is enabled for zone {zone.name}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Automatic HTTPS Rewrites is not enabled for zone {zone.name}."
                )
            findings.append(report)
        return findings
