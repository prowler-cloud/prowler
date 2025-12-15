from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_hsts_enabled(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        # Recommended minimum max-age is 6 months (15768000 seconds)
        recommended_max_age = 15768000

        for zone in zones_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            hsts = zone.settings.strict_transport_security
            if hsts.enabled:
                if not hsts.include_subdomains:
                    report.status = "FAIL"
                    report.status_extended = f"HSTS is enabled for zone {zone.name} but does not include subdomains."
                elif hsts.max_age < recommended_max_age:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"HSTS is enabled for zone {zone.name} but max-age is "
                        f"{hsts.max_age} seconds (recommended: 6 months)."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"HSTS is enabled for zone {zone.name} with max-age of "
                        f"{hsts.max_age} seconds and includes subdomains."
                    )
            else:
                report.status = "FAIL"
                report.status_extended = f"HSTS is not enabled for zone {zone.name}."
            findings.append(report)
        return findings
