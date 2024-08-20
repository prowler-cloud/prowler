from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_lifecycle_enabled(Check):
    def execute(self):
        findings = []
        min_expiration_days = s3_client.audit_config.get("min_expiration_days", 1)
        max_expiration_days = s3_client.audit_config.get("max_expiration_days", 36500)
        min_transition_days = s3_client.audit_config.get("min_transition_days", 1)
        max_transition_days = s3_client.audit_config.get("max_transition_days", 36500)
        valid_storage_transition_classes = s3_client.audit_config.get(
            "valid_lifecycle_transition_storage_classes",
            [
                "STANDARD_IA",
                "INTELLIGENT_TIERING",
                "ONEZONE_IA",
                "GLACIER",
                "GLACIER_IR",
                "DEEP_ARCHIVE",
            ],
        )

        logger.error(min_expiration_days)
        logger.error(max_expiration_days)
        logger.error(min_transition_days)
        logger.error(max_transition_days)
        logger.error(valid_storage_transition_classes)

        for arn, bucket in s3_client.buckets.items():
            report = Check_Report_AWS(self.metadata())
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = arn
            report.resource_tags = bucket.tags
            report.status = "FAIL"
            report.status_extended = f"S3 Bucket {bucket.name} does not have a correct Lifecycle Configuration."

            if bucket.lifecycle:
                for rule in bucket.lifecycle:
                    if (
                        rule.status == "Enabled"
                        and (
                            min_expiration_days
                            <= rule.expiration_days
                            <= max_expiration_days
                        )
                        and (
                            min_transition_days
                            <= rule.transition_days
                            <= max_transition_days
                        )
                        and rule.transition_storage_class
                        in valid_storage_transition_classes
                    ):
                        report.status = "PASS"
                        report.status_extended = f"At least one LifeCycle Configuration is correct for S3 Bucket {bucket.name}."
                        break

            findings.append(report)

        return findings
