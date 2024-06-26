from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_instance_confidential_computing_enabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in compute_client.instances:
            report = Check_Report_GCP(self.metadata())
            report.project_id = instance.project_id
            report.resource_id = instance.id
            report.resource_name = instance.name
            report.location = instance.zone
            report.status = "PASS"
            report.status_extended = (
                f"VM Instance {instance.name} has Confidential Computing enabled."
            )
            if not instance.confidential_computing:
                report.status = "FAIL"
                report.status_extended = f"VM Instance {instance.name} does not have Confidential Computing enabled."
            findings.append(report)

        return findings
