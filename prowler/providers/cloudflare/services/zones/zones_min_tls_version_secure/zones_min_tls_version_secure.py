from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.config import CLOUDFLARE_DEFAULT_MIN_TLS
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_min_tls_version_secure(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        required_version = float(CLOUDFLARE_DEFAULT_MIN_TLS)

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
            if current >= required_version:
                report.status = "PASS"
                report.status_extended = f"Minimum TLS version for zone {zone.name} is set to {current_version}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Minimum TLS version for zone {zone.name} is {current_version}, below the recommended {CLOUDFLARE_DEFAULT_MIN_TLS}."
            findings.append(report)
        return findings
