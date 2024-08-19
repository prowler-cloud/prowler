from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client
from prowler.providers.aws.services.s3.s3_service import StorageClass


class s3_bucket_lifecycle_enabled(Check):
    def execute(self):
        findings = []
        for arn, bucket in s3_client.buckets.items():
            report = Check_Report_AWS(self.metadata())
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = arn
            report.resource_tags = bucket.tags
            report.status = "PASS"
            report.status_extended = f"All S3 Bucket {bucket.name} Lifecycle configurations are valid and enabled."

            if bucket.lifecycle:
                for rule in bucket.lifecycle:
                    if not (
                        rule.status == "Enabled"
                        and 1 <= rule.expiration_days <= 36500
                        and 1 <= rule.transition_days <= 36500
                        and rule.transition_storage_class in StorageClass
                    ):
                        report.status = "FAIL"
                        report.status_extended = f"S3 Bucket {bucket.name} has Lifecycle rule {rule.id} disabled or misconfigurated."
                        break
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} does not have Lifecycle Configuration."
                )

            findings.append(report)

        return findings
