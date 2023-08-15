from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudstorage.cloudstorage_client import (
    cloudstorage_client,
)


class cloudstorage_bucket_uniform_bucket_level_access(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for bucket in cloudstorage_client.buckets:
            report = Check_Report_GCP(self.metadata())
            report.project_id = bucket.project_id
            report.resource_id = bucket.id
            report.resource_name = bucket.name
            report.location = bucket.region
            report.status = "PASS"
            report.status_extended = (
                f"Bucket {bucket.name} has uniform Bucket Level Access enabled."
            )
            if not bucket.uniform_bucket_level_access:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bucket {bucket.name} has uniform Bucket Level Access disabled."
                )
            findings.append(report)

        return findings
