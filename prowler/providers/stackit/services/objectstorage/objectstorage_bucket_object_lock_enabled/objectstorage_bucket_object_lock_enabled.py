from prowler.lib.check.models import Check, CheckReportStackIT
from prowler.providers.stackit.services.objectstorage.objectstorage_client import (
    objectstorage_client,
)


class objectstorage_bucket_object_lock_enabled(Check):
    def execute(self):
        findings = []
        for bucket in objectstorage_client.buckets:
            report = CheckReportStackIT(
                metadata=self.metadata(),
                resource=bucket,
            )
            report.resource_id = bucket.name
            report.resource_name = bucket.name
            report.location = bucket.region

            if bucket.object_lock_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Bucket {bucket.name} has S3 Object Lock enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bucket {bucket.name} does not have S3 Object Lock enabled."
                )

            findings.append(report)
        return findings
