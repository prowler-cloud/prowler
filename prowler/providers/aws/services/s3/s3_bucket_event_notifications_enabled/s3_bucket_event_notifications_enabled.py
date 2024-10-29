from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_event_notifications_enabled(Check):
    def execute(self):
        findings = []
        for arn, bucket in s3_client.buckets.items():
            report = Check_Report_AWS(self.metadata())
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = arn
            report.resource_tags = bucket.tags
            report.status = "FAIL"
            report.status_extended = (
                f"S3 Bucket {bucket.name} does not have event notifications enabled."
            )

            logger.error("NOTIFICATION CONFIG:")
            logger.error(bucket.notification_config)
            if bucket.notification_config:
                report.status = "PASS"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} does have event notifications enabled."
                )

            findings.append(report)

        return findings
