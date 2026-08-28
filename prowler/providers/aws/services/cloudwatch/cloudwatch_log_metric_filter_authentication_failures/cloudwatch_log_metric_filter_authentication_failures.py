from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.cloudwatch.cloudwatch_client import (
    cloudwatch_client,
)
from prowler.providers.aws.services.cloudwatch.lib.metric_filters import (
    build_metric_filter_pattern,
    check_cloudwatch_log_metric_filter,
)
from prowler.providers.aws.services.cloudwatch.logs_client import logs_client


class cloudwatch_log_metric_filter_authentication_failures(Check):
    def execute(self):
        pattern = build_metric_filter_pattern(
            event_names=["ConsoleLogin"],
            extra_clauses=[("errorMessage", "=", "Failed authentication")],
        )
        findings = []

        report = check_cloudwatch_log_metric_filter(
            pattern,
            cloudtrail_client.trails,
            logs_client.metric_filters,
            cloudwatch_client.metric_alarms,
            self.metadata(),
        )

        inventory_unavailable = (
            cloudtrail_client.trails_unavailable
            or logs_client.metric_filters_unavailable
            or cloudwatch_client.metric_alarms_unavailable
        )

        if report is None:
            report = Check_Report_AWS(metadata=self.metadata(), resource={})
            report.status = "FAIL"
            report.status_extended = "No CloudWatch log groups found with metric filters or alarms associated."
            report.region = logs_client.region
            report.resource_id = logs_client.audited_account
            report.resource_arn = logs_client.log_group_arn_template
            report.resource_tags = []

        # A denied listing in any region means the inventory is incomplete: a
        # PASS is still backed by a real filter and alarm, but a FAIL (nothing
        # found, or a filter found without its alarm) cannot be trusted.
        if report.status == "FAIL" and inventory_unavailable:
            report.status = "MANUAL"
            report.status_extended = "Cannot evaluate CloudWatch metric filters and alarms: CloudTrail trails, metric filters or alarms could not be listed in at least one region. Verify that the scanning credentials are allowed to call cloudtrail:DescribeTrails, logs:DescribeMetricFilters and cloudwatch:DescribeAlarms."

        findings.append(report)

        return findings
