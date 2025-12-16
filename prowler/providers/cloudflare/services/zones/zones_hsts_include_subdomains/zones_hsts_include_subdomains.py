from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_hsts_include_subdomains(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for zone in zones_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            hsts = zone.settings.strict_transport_security
            if hsts.enabled and hsts.include_subdomains:
                report.status = "PASS"
                report.status_extended = f"HSTS is enabled with includeSubDomains directive for zone {zone.name}."
            elif hsts.enabled:
                report.status = "FAIL"
                report.status_extended = f"HSTS is enabled but does not include subdomains for zone {zone.name}."
            else:
                report.status = "FAIL"
                report.status_extended = f"HSTS is not enabled for zone {zone.name}."
            findings.append(report)
        return findings
