import re

from prowler.lib.check.models import Check_Report_AWS


def check_cloudwatch_log_metric_filter(
    metric_filter_pattern: str,
    trails: list,
    metric_filters: list,
    metric_alarms: list,
    metadata: dict,
):
    report = None
    # 1. Iterate for CloudWatch Log Group in CloudTrail trails
    log_groups = []
    if trails is not None and metric_filters is not None and metric_alarms is not None:
        report = Check_Report_AWS(metadata)
        for trail in trails.values():
            if trail.log_group_arn:
                log_groups.append(trail.log_group_arn.split(":")[6])
        # 2. Describe metric filters for previous log groups
        for metric_filter in metric_filters:
            if metric_filter.log_group.name in log_groups and re.search(
                metric_filter_pattern, metric_filter.pattern, flags=re.DOTALL
            ):
                report.resource_id = metric_filter.log_group.name
                report.resource_arn = metric_filter.log_group.arn
                report.region = metric_filter.log_group.region
                report.resource_tags = getattr(metric_filter.log_group, "tags", [])
                report.status = "FAIL"
                report.status_extended = f"CloudWatch log group {metric_filter.log_group.name} found with metric filter {metric_filter.name} but no alarms associated."
                # 3. Check if there is an alarm for the metric
                for alarm in metric_alarms:
                    if alarm.metric == metric_filter.metric:
                        report.status = "PASS"
                        report.status_extended = f"CloudWatch log group {metric_filter.log_group.name} found with metric filter {metric_filter.name} and alarms set."
                        break
                if report.status == "PASS":
                    break

    return report
