from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_hsts_enabled(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        # Recommended minimum max-age is 6 months (15768000 seconds)
        recommended_max_age = 15768000

        for zone in zones_client.zones:
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            if zone.settings.hsts_enabled:
                if zone.settings.hsts_max_age >= recommended_max_age:
                    report.status = "PASS"
                    report.status_extended = (
                        f"HSTS is enabled for zone {zone.name} with max-age of "
                        f"{zone.settings.hsts_max_age} seconds."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"HSTS is enabled for zone {zone.name} but max-age is "
                        f"{zone.settings.hsts_max_age} seconds (recommended: {recommended_max_age})."
                    )
            else:
                report.status = "FAIL"
                report.status_extended = f"HSTS is not enabled for zone {zone.name}."
            findings.append(report)
        return findings
