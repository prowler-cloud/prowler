from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.cloudwatch.cloudwatch_client import (
    cloudwatch_client,
)
from prowler.providers.aws.services.cloudwatch.lib.metric_filters import (
    check_cloudwatch_log_metric_filter,
)
from prowler.providers.aws.services.cloudwatch.logs_client import logs_client


class cloudwatch_log_metric_filter_for_s3_bucket_policy_changes(Check):
    def execute(self):
        pattern = r"\$\.eventSource\s*=\s*.?s3.amazonaws.com.+\$\.eventName\s*=\s*.?PutBucketAcl.+\$\.eventName\s*=\s*.?PutBucketPolicy.+\$\.eventName\s*=\s*.?PutBucketCors.+\$\.eventName\s*=\s*.?PutBucketLifecycle.+\$\.eventName\s*=\s*.?PutBucketReplication.+\$\.eventName\s*=\s*.?DeleteBucketPolicy.+\$\.eventName\s*=\s*.?DeleteBucketCors.+\$\.eventName\s*=\s*.?DeleteBucketLifecycle.+\$\.eventName\s*=\s*.?DeleteBucketReplication.?"
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.status = "FAIL"
        report.status_extended = (
            "No CloudWatch log groups found with metric filters or alarms associated."
        )
        report.region = cloudwatch_client.region
        report.resource_id = logs_client.audited_account
        report.resource_arn = logs_client.log_group_arn_template

        report = check_cloudwatch_log_metric_filter(
            pattern,
            cloudtrail_client.trails,
            logs_client.metric_filters,
            cloudwatch_client.metric_alarms,
            report,
        )

        findings.append(report)
        return findings
