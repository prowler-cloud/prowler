from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_object_versioning(Check):
    def execute(self):
        findings = []
        for bucket in s3_client.buckets.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=bucket)
            if bucket.versioning:
                report.status = "PASS"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} has versioning enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} has versioning disabled."
                )
            findings.append(report)

        return findings
