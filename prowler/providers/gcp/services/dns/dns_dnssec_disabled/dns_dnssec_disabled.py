from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.dns.dns_client import dns_client


class dns_dnssec_disabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for managed_zone in dns_client.managed_zones:
            report = Check_Report_GCP(self.metadata())
            report.project_id = managed_zone.project_id
            report.resource_id = managed_zone.id
            report.resource_name = managed_zone.name
            report.status = "PASS"
            report.status_extended = (
                f"Cloud DNS {managed_zone.name} have DNSSEC enabled."
            )
            if not managed_zone.dnssec:
                report.status = "FAIL"
                report.status_extended = (
                    f"Cloud DNS {managed_zone.name} doens't have DNSSEC enabled."
                )
            findings.append(report)

        return findings
