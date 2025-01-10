from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_client import bedrock_client


class bedrock_model_invocation_logging_enabled(Check):
    def execute(self):
        findings = []
        for region, logging in bedrock_client.logging_configurations.items():
            report = Check_Report_AWS(self.metadata())
            report.region = region
            report.resource_id = "model-invocation-logging"
            report.resource_arn = (
                bedrock_client._get_model_invocation_logging_arn_template(region)
            )
            report.status = "FAIL"
            report.status_extended = "Bedrock Model Invocation Logging is disabled."
            if logging.enabled:
                report.status = "PASS"
                report.status_extended = "Bedrock Model Invocation Logging is enabled"
                if logging.cloudwatch_log_group and logging.s3_bucket:
                    report.status_extended += f" in CloudWatch Log Group: {logging.cloudwatch_log_group} and S3 Bucket: {logging.s3_bucket}."
                elif logging.cloudwatch_log_group:
                    report.status_extended += (
                        f" in CloudWatch Log Group: {logging.cloudwatch_log_group}."
                    )
                elif logging.s3_bucket:
                    report.status_extended += f" in S3 Bucket: {logging.s3_bucket}."

            findings.append(report)

        return findings
