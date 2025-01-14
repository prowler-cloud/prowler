from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.dns.dns_client import dns_client


class dns_dnssec_disabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for managed_zone in dns_client.managed_zones:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource_metadata=managed_zone,
                location=dns_client.region,
            )
            report.status = "PASS"
            report.status_extended = (
                f"Cloud DNS {managed_zone.name} has DNSSEC enabled."
            )
            if not managed_zone.dnssec:
                report.status = "FAIL"
                report.status_extended = (
                    f"Cloud DNS {managed_zone.name} doesn't have DNSSEC enabled."
                )
            findings.append(report)

        return findings
