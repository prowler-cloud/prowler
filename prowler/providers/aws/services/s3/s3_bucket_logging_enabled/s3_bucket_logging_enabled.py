from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_logging_enabled(Check):
    def execute(self):
        findings = []

        for bucket in s3_client.buckets.values():
            report = Check_Report_AWS(self.metadata())
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_tags = bucket.tags

            if bucket.logging:
                report.status = "PASS"
                report.status_extended = f"S3 bucket {bucket.name} has logging enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"S3 bucket {bucket.name} does not have logging enabled."

            findings.append(report)

        return findings
