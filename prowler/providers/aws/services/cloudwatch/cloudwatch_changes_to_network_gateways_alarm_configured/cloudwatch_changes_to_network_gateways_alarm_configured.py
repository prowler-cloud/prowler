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


class cloudwatch_changes_to_network_gateways_alarm_configured(Check):
    def execute(self):
        pattern = r"\$\.eventName\s*=\s*.?CreateCustomerGateway.+\$\.eventName\s*=\s*.?DeleteCustomerGateway.+\$\.eventName\s*=\s*.?AttachInternetGateway.+\$\.eventName\s*=\s*.?CreateInternetGateway.+\$\.eventName\s*=\s*.?DeleteInternetGateway.+\$\.eventName\s*=\s*.?DetachInternetGateway.?"
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
