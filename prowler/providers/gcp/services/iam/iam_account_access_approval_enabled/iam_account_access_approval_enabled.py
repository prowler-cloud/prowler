from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.iam.accessapproval_client import (
    accessapproval_client,
)


class iam_account_access_approval_enabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for project_id in accessapproval_client.project_ids:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource_metadata=accessapproval_client.projects[project_id],
                resource_id=project_id,
                location=accessapproval_client.region,
            )
            report.status = "PASS"
            report.status_extended = (
                f"Project {project_id} has Access Approval enabled."
            )
            if project_id not in accessapproval_client.settings:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {project_id} does not have Access Approval enabled."
                )
            findings.append(report)

        return findings
