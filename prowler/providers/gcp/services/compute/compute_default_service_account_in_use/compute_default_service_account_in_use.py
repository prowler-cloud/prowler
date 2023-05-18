from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_default_service_account_in_use(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in compute_client.instances:
            report = Check_Report_GCP(self.metadata())
            report.project_id = compute_client.project_id
            report.resource_id = instance.id
            report.resource_name = instance.name
            report.location = instance.zone
            report.status = "PASS"
            report.status_extended = f"The default service account is not configured to be used with VM Instance {instance.name}"
            if any([(sa["email"] == f"{compute_client.project_id}-compute@developer.gserviceaccount.com") for sa in instance.service_accounts]) \
               and instance.name[:4] != 'gke-':
                report.status = "FAIL"
                report.status_extended = f"The default service account is configured to be used with VM Instance {instance.name}"
            findings.append(report)

        return findings
