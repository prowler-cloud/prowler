from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_dnssec_enabled(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for zone in zones_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            if zone.dnssec_status == "active":
                report.status = "PASS"
                report.status_extended = f"DNSSEC is enabled for zone {zone.name}."
            else:
                report.status = "FAIL"
                report.status_extended = f"DNSSEC is not enabled for zone {zone.name}."
            findings.append(report)
        return findings
