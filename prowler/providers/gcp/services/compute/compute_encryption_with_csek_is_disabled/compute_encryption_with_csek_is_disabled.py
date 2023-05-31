from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_encryption_with_csek_is_disabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in compute_client.instances:
            report = Check_Report_GCP(self.metadata())
            report.project_id = compute_client.project_id
            report.resource_id = instance.id
            report.resource_name = instance.name
            report.location = instance.zone
            report.status = "FAIL"
            report.status_extended = f"The VM Instance {instance.name} have the following unencrypted disks: '{', '.join([i[0] for i in instance.disks_encryption if not i[1]])}'"
            if all([i[1] for i in instance.disks_encryption]):
                report.status = "PASS"
                report.status_extended = (
                    f"The VM Instance {instance.name} have every disk encrypted."
                )
            findings.append(report)

        return findings
