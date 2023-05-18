from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_default_service_account_in_use_with_full_api_access(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in compute_client.instances:
            report = Check_Report_GCP(self.metadata())
            report.project_id = compute_client.project_id
            report.resource_id = instance.id
            report.resource_name = instance.name
            report.location = instance.zone
            report.status = "PASS"
            report.status_extended = f"The VM Instance {instance.name} is not configured to use the default service account with full access to all cloud APIs "
            scopes_emails = []
            for sa in instance.service_accounts:
                for email in sa["scopes"]:
                    scopes_emails.append(email)
            if any([email == f"{compute_client.project_id}-compute@developer.gserviceaccount.com" for email in scopes_emails]) \
               and instance.name[:4] != 'gke-':
                report.status = "FAIL"
                report.status_extended = f"The VM Instance {instance.name} is configured to use the default service account with full access to all cloud APIs "
            findings.append(report)

        return findings
