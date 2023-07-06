from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_client import (
    cloudresourcemanager_client,
)


class iam_role_sa_enforce_separation_of_duties(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for project in cloudresourcemanager_client.project_ids:
            non_compliant_members = []
            report = Check_Report_GCP(self.metadata())
            report.project_id = project
            report.location = cloudresourcemanager_client.region
            report.resource_id = project
            report.status = "PASS"
            report.status_extended = f"Principle of separation of duties was enforced for Service-Account Related Roles in project {project}"
            for binding in cloudresourcemanager_client.bindings:
                if binding.project_id == project and (
                    "roles/iam.serviceAccountUser" in binding.role
                    or "roles/iam.serviceAccountAdmin" in binding.role
                ):
                    non_compliant_members.extend(binding.members)
            if non_compliant_members:
                report.status = "FAIL"
                report.status_extended = f"Principle of separation of duties was not enforced for Service-Account Related Roles in project {project} in members {','.join(non_compliant_members)}"
            findings.append(report)

        return findings
