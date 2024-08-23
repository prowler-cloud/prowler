from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_lifecycle_enabled(Check):
    def execute(self):
        findings = []
        for arn, bucket in s3_client.buckets.items():
            report = Check_Report_AWS(self.metadata())
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = arn
            report.resource_tags = bucket.tags
            report.status = "FAIL"
            report.status_extended = f"S3 Bucket {bucket.name} does not have a lifecycle configuration enabled."

            if bucket.lifecycle:
                for configuration in bucket.lifecycle:
                    if configuration.status == "Enabled":
                        report.status = "PASS"
                        report.status_extended = f"S3 Bucket {bucket.name} has a lifecycle configuration enabled."
                        break

            findings.append(report)

        return findings
