from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_replication_enabled(Check):
    def execute(self):
        findings = []
        for bucket in s3_client.buckets.values():
            report = Check_Report_AWS(self.metadata())
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_tags = bucket.tags

            # Construct ARN (Amazon Resource Name) from bucket name
            bucket_arn = f"arn:aws:s3:::{bucket.name}"
            report.resource_arn = bucket_arn

            # Check if the bucket has replication rules enabled
            if hasattr(bucket, "replication_rules") and bucket.replication_rules:
                report.status = "PASS"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} has replication rules enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} does not have replication rules enabled."
                )

            findings.append(report)
        return findings
