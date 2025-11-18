from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.accesscontextmanager.accesscontextmanager_client import (
    accesscontextmanager_client,
)
from prowler.providers.gcp.services.cloudstorage.cloudstorage_client import (
    cloudstorage_client,
)


class cloudstorage_bucket_uses_vpc_service_controls(Check):
    """
    Ensure Cloud Storage buckets are protected by VPC Service Controls.

    Reports PASS if a bucket's project is in a VPC Service Controls perimeter
    with storage.googleapis.com as a restricted service, otherwise FAIL.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []

        protected_projects = {}
        for perimeter in accesscontextmanager_client.service_perimeters:
            if "storage.googleapis.com" in perimeter.restricted_services:
                for resource in perimeter.resources:
                    protected_projects[resource] = perimeter.title

        for bucket in cloudstorage_client.buckets:
            report = Check_Report_GCP(metadata=self.metadata(), resource=bucket)
            report.status = "FAIL"
            report.status_extended = (
                f"Bucket {bucket.name} is not protected by VPC Service Controls."
            )
            project_resource_id = f"projects/{bucket.project_id}"

            if project_resource_id in protected_projects:
                report.status = "PASS"
                report.status_extended = f"Bucket {bucket.name} is protected by VPC Service Controls perimeter {protected_projects[project_resource_id]}."

            findings.append(report)

        return findings
