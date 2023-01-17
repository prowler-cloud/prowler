import re

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.cloudwatch.cloudwatch_client import (
    cloudwatch_client,
)
from prowler.providers.aws.services.cloudwatch.logs_client import logs_client


class cloudwatch_changes_to_network_route_tables_alarm_configured(Check):
    def execute(self):
        pattern = r"\$\.eventName\s*=\s*CreateRoute.+\$\.eventName\s*=\s*CreateRouteTable.+\$\.eventName\s*=\s*ReplaceRoute.+\$\.eventName\s*=\s*ReplaceRouteTableAssociation.+\$\.eventName\s*=\s*DeleteRouteTable.+\$\.eventName\s*=\s*DeleteRoute.+\$\.eventName\s*=\s*DisassociateRouteTable"
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.status = "FAIL"
        report.status_extended = (
            "No CloudWatch log groups found with metric filters or alarms associated."
        )
        report.region = cloudwatch_client.region
        report.resource_id = cloudtrail_client.audited_account
        # 1. Iterate for CloudWatch Log Group in CloudTrail trails
        log_groups = []
        for trail in cloudtrail_client.trails:
            if trail.log_group_arn:
                log_groups.append(trail.log_group_arn.split(":")[6])
        # 2. Describe metric filters for previous log groups
        for metric_filter in logs_client.metric_filters:
            if metric_filter.log_group in log_groups:
                if re.search(pattern, metric_filter.pattern):
                    report.resource_id = metric_filter.log_group
                    report.region = metric_filter.region
                    report.status = "FAIL"
                    report.status_extended = f"CloudWatch log group {metric_filter.log_group} found with metric filter {metric_filter.name} but no alarms associated."
                    # 3. Check if there is an alarm for the metric
                    for alarm in cloudwatch_client.metric_alarms:
                        if alarm.metric == metric_filter.metric:
                            report.status = "PASS"
                            report.status_extended = f"CloudWatch log group {metric_filter.log_group} found with metric filter {metric_filter.name} and alarms set."
                            break

        findings.append(report)
        return findings
