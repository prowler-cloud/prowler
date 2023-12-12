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


class cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled(
    Check
):
    def execute(self):
        pattern = r"\$\.eventSource\s*=\s*.?config.amazonaws.com.+\$\.eventName\s*=\s*.?StopConfigurationRecorder.+\$\.eventName\s*=\s*.?DeleteDeliveryChannel.+\$\.eventName\s*=\s*.?PutDeliveryChannel.+\$\.eventName\s*=\s*.?PutConfigurationRecorder.?"
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.status = "FAIL"
        report.status_extended = (
            "No CloudWatch log groups found with metric filters or alarms associated."
        )
        report.region = cloudwatch_client.region
        report.resource_id = cloudtrail_client.audited_account
        report.resource_arn = cloudtrail_client.audited_account_arn
        report = check_cloudwatch_log_metric_filter(
            pattern,
            cloudtrail_client.trails,
            logs_client.metric_filters,
            cloudwatch_client.metric_alarms,
            report,
        )

        findings.append(report)
        return findings
