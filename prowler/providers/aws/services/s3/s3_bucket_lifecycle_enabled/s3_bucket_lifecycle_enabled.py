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
            report.status_extended = f"S3 Bucket {bucket.name} does not have a correct Lifecycle Configuration."

            if bucket.lifecycle and len(bucket.lifecycle) == 1:
                rule = bucket.lifecycle[0]
                if (
                    rule.status == "Enabled"
                    and 1 <= rule.expiration_days <= 36500
                    and 1 <= rule.transition_days <= 36500
                    and rule.transition_storage_class
                    in [
                        "STANDARD_IA",
                        "INTELLIGENT_TIERING",
                        "ONEZONE_IA",
                        "GLACIER",
                        "GLACIER_IR",
                        "DEEP_ARCHIVE",
                    ]
                ):
                    report.status = "PASS"
                    report.status_extended = f"At least one LifeCycle Configuration is correct for S3 Bucket {bucket.name}."
                    break

        findings.append(report)

        return findings
