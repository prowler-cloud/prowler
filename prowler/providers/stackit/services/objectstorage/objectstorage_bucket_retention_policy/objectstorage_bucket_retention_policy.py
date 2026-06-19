from prowler.lib.check.models import Check, CheckReportStackIT
from prowler.providers.stackit.services.objectstorage.objectstorage_client import (
    objectstorage_client,
)


class objectstorage_bucket_retention_policy(Check):
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

            if bucket.retention_days and bucket.retention_days > 0:
                report.status = "PASS"
                report.status_extended = (
                    f"Bucket {bucket.name} has a default retention policy of "
                    f"{bucket.retention_days} day(s) in {bucket.retention_mode} mode."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"Bucket {bucket.name} does not have a default retention policy configured."

            findings.append(report)
        return findings
