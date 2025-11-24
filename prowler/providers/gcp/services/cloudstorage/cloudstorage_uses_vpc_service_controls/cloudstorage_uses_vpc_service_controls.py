from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.accesscontextmanager.accesscontextmanager_client import (
    accesscontextmanager_client,
)
from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_client import (
    cloudresourcemanager_client,
)


class cloudstorage_uses_vpc_service_controls(Check):
    """
    Ensure Cloud Storage is protected by VPC Service Controls at project level.

    Reports PASS if a project is in a VPC Service Controls perimeter
    with storage.googleapis.com as a restricted service, otherwise FAIL.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []

        protected_projects = {}
        for perimeter in accesscontextmanager_client.service_perimeters:
            if any(
                service == "storage.googleapis.com"
                for service in perimeter.restricted_services
            ):
                for resource in perimeter.resources:
                    protected_projects[resource] = perimeter.title

        for project in cloudresourcemanager_client.cloud_resource_manager_projects:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=cloudresourcemanager_client.projects[project.id],
                project_id=project.id,
                location=cloudresourcemanager_client.region,
                resource_name=(
                    cloudresourcemanager_client.projects[project.id].name
                    if cloudresourcemanager_client.projects[project.id].name
                    else "GCP Project"
                ),
            )
            report.status = "FAIL"
            report.status_extended = f"Project {project.id} does not have VPC Service Controls enabled for Cloud Storage."
            project_resource_id = f"projects/{project.id}"

            if project_resource_id in protected_projects:
                report.status = "PASS"
                report.status_extended = f"Project {project.id} has VPC Service Controls enabled for Cloud Storage in perimeter {protected_projects[project_resource_id]}."

            findings.append(report)

        return findings
