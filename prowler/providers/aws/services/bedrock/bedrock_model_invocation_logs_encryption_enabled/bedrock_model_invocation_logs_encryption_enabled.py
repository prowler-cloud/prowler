from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_client import bedrock_client
from prowler.providers.aws.services.cloudwatch.logs_client import logs_client
from prowler.providers.aws.services.s3.s3_client import s3_client


class bedrock_model_invocation_logs_encryption_enabled(Check):
    def execute(self):
        findings = []
        for region, logging in bedrock_client.logging_configurations.items():
            if logging.enabled:
                s3_encryption = True
                cloudwatch_encryption = True
                report = Check_Report_AWS(self.metadata())
                report.region = region
                report.resource_id = "model-invocation-logging"
                report.resource_arn = (
                    bedrock_client._get_model_invocation_logging_arn_template(region)
                )
                report.status = "PASS"
                report.status_extended = "Bedrock Model Invocation logs are encrypted."
                if logging.s3_bucket:
                    bucket_arn = (
                        f"arn:{s3_client.audited_partition}:s3:::{logging.s3_bucket}"
                    )
                    if (
                        bucket_arn in s3_client.buckets
                        and not s3_client.buckets[bucket_arn].encryption
                    ):
                        s3_encryption = False
                if logging.cloudwatch_log_group:
                    log_group_arn = f"arn:{logs_client.audited_partition}:logs:{region}:{logs_client.audited_account}:log-group:{logging.cloudwatch_log_group}"
                    if (
                        log_group_arn in logs_client.log_groups
                        and not logs_client.log_groups[log_group_arn].kms_id
                    ) or (
                        log_group_arn + ":*" in logs_client.log_groups
                        and not logs_client.log_groups[log_group_arn + ":*"].kms_id
                    ):
                        cloudwatch_encryption = False
                if not s3_encryption and not cloudwatch_encryption:
                    report.status = "FAIL"
                    report.status_extended = f"Bedrock Model Invocation logs are not encrypted in S3 bucket: {logging.s3_bucket} and CloudWatch Log Group: {logging.cloudwatch_log_group}."
                elif not s3_encryption:
                    report.status = "FAIL"
                    report.status_extended = f"Bedrock Model Invocation logs are not encrypted in S3 bucket: {logging.s3_bucket}."
                elif not cloudwatch_encryption:
                    report.status = "FAIL"
                    report.status_extended = f"Bedrock Model Invocation logs are not encrypted in CloudWatch Log Group: {logging.cloudwatch_log_group}."

                findings.append(report)

        return findings
