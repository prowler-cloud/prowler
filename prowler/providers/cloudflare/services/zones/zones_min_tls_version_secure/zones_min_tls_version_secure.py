from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_min_tls_version_secure(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []

        for zone in zones_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            current_version = zone.settings.min_tls_version or "0"
            try:
                current = float(current_version)
            except ValueError:
                current = 0

            if current >= 1.2:
                report.status = "PASS"
                report.status_extended = f"Minimum TLS version for zone {zone.name} is set to {current_version}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Minimum TLS version for zone {zone.name} is {current_version}, below the recommended 1.2."
            findings.append(report)
        return findings
