from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_instance_encryption_with_csek_enabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in compute_client.instances:
            report = Check_Report_GCP(metadata=self.metadata(), resource=instance)
            report.status = "FAIL"
            report.status_extended = (
                f"The VM Instance {instance.name} has the following disks not encrypted with CSEK: '{', '.join([i[0] for i in instance.disks_encryption if not i[1]])}'. "
                "CSEK can no longer be applied to Compute Engine resources since July 20, 2026, so this finding is not remediable; Google recommends CMEK instead. "
                "This check will be deprecated on July 20, 2027, when CSEK is removed from Compute Engine."
            )
            if all([i[1] for i in instance.disks_encryption]):
                report.status = "PASS"
                report.status_extended = f"The VM Instance {instance.name} has every disk encrypted with CSEK."
            findings.append(report)

        return findings
