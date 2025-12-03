from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_waf_enabled(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for zone in zones_client.zones:
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            waf_setting = (zone.settings.waf or "").lower()

            if waf_setting == "on":
                report.status = "PASS"
                report.status_extended = f"WAF is enabled for zone {zone.name}."
            else:
                report.status = "FAIL"
                report.status_extended = f"WAF is not enabled for zone {zone.name}."
            findings.append(report)
        return findings
