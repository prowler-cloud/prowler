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


class cloudwatch_log_metric_filter_root_usage(Check):
    def execute(self):
        pattern = r"\$\.userIdentity\.type\s*=\s*.?Root.+\$\.userIdentity\.invokedBy NOT EXISTS.+\$\.eventType\s*!=\s*.?AwsServiceEvent.?"
        findings = []

        report = check_cloudwatch_log_metric_filter(
            pattern,
            cloudtrail_client.trails,
            logs_client.metric_filters,
            cloudwatch_client.metric_alarms,
            self.metadata(),
        )

        if report is None:
            report = Check_Report_AWS(metadata=self.metadata(), resource={})
            if (
                cloudtrail_client.trails_unavailable
                or logs_client.metric_filters_unavailable
                or cloudwatch_client.metric_alarms_unavailable
            ):
                # A denied listing in any region means the inventory is
                # incomplete, so the absence of a matching filter/alarm cannot
                # be treated as a finding.
                report.status = "MANUAL"
                report.status_extended = "Cannot evaluate CloudWatch metric filters and alarms: CloudTrail trails, metric filters or alarms could not be listed in at least one region. Verify that the scanning credentials are allowed to call cloudtrail:DescribeTrails, logs:DescribeMetricFilters and cloudwatch:DescribeAlarms."
            else:
                report.status = "FAIL"
                report.status_extended = "No CloudWatch log groups found with metric filters or alarms associated."
            report.region = logs_client.region
            report.resource_id = logs_client.audited_account
            report.resource_arn = logs_client.log_group_arn_template
            report.resource_tags = []

        findings.append(report)

        return findings
