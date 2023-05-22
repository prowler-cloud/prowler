from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_shielded_vm_enabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in compute_client.instances:
            report = Check_Report_GCP(self.metadata())
            report.project_id = compute_client.project_id
            report.resource_id = instance.id
            report.resource_name = instance.name
            report.location = instance.zone
            report.status = "PASS"
            report.status_extended = f"VM Instance {instance.name} have vTPM or Integrity Monitoring set to on"
            if (
                not instance.shielded_enabled_vtpm
                or not instance.shielded_enabled_integrity_monitoring
            ):
                report.status = "FAIL"
                report.status_extended = f"VM Instance {instance.name} don't have vTPM and Integrity Monitoring set to on"
            findings.append(report)

        return findings
