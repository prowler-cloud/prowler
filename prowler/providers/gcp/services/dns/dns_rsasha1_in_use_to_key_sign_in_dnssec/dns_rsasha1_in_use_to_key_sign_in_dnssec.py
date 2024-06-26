from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.dns.dns_client import dns_client


class dns_rsasha1_in_use_to_key_sign_in_dnssec(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for managed_zone in dns_client.managed_zones:
            report = Check_Report_GCP(self.metadata())
            report.project_id = managed_zone.project_id
            report.resource_id = managed_zone.id
            report.resource_name = managed_zone.name
            report.status = "PASS"
            report.status_extended = f"Cloud DNS {managed_zone.name} is not using RSASHA1 algorithm as key signing."
            if any(
                [
                    key["algorithm"] == "rsasha1"
                    for key in managed_zone.key_specs
                    if key["keyType"] == "keySigning"
                ]
            ):
                report.status = "FAIL"
                report.status_extended = f"Cloud DNS {managed_zone.name} is using RSASHA1 algorithm as key signing."
            findings.append(report)

        return findings
