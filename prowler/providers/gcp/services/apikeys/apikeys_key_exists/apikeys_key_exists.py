from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.apikeys.apikeys_client import apikeys_client


class apikeys_key_exists(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for project in apikeys_client.project_ids:
            report = Check_Report_GCP(self.metadata())
            report.project_id = project
            report.resource_id = project
            report.location = apikeys_client.region
            report.status = "PASS"
            report.status_extended = f"Project {project} does not have active API Keys."
            for key in apikeys_client.keys:
                if key.project_id == project:
                    report.status = "FAIL"
                    report.status_extended = f"Project {project} has active API Keys."
                    break
            findings.append(report)

        return findings
