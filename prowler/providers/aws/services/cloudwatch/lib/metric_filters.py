import re

from prowler.lib.check.models import Check_Report_AWS


def build_metric_filter_pattern(
    *,
    event_names: list[str] | None = None,
    event_source: str | None = None,
    extra_clauses: list[tuple[str, str, str]] | None = None,
) -> str:
    """Build a regex pattern to match a CloudWatch Logs filterPattern string.

    All clauses must be present for the pattern to match, regardless of the
    order in which AWS stores them. Event names are matched exactly, so a
    short name like ``CreateRoute`` will not be satisfied by a longer one
    like ``CreateRouteTable``.

    Pass the result directly to ``check_cloudwatch_log_metric_filter``.

    Args:
        event_names: AWS API action names to require (``$.eventName``).
        event_source: optional service principal to require (``$.eventSource``),
            e.g. ``"ec2.amazonaws.com"``.
        extra_clauses: additional conditions as ``(field, operator, value)``
            tuples, where ``operator`` is ``"="`` or ``"!="``. Example:
            ``("additionalEventData.MFAUsed", "!=", "Yes")``.

    Returns:
        A regex string for use with ``re.search(..., flags=re.DOTALL)``.
    """
    parts: list[str] = []
    if event_source is not None:
        parts.append(rf"(?=.*\$\.eventSource\s*=\s*.?{re.escape(event_source)})")
    for name in event_names or []:
        parts.append(rf"(?=.*\$\.eventName\s*=\s*.?{re.escape(name)}(?![A-Za-z]))")
    for field, operator, value in extra_clauses or []:
        op = r"\s*!=\s*" if operator == "!=" else r"\s*=\s*"
        parts.append(rf"(?=.*\$\.{re.escape(field)}{op}.?{re.escape(value)})")
    return "".join(parts)


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
        for trail in trails.values():
            if trail.log_group_arn:
                log_groups.append(trail.log_group_arn.split(":")[6])
        # 2. Describe metric filters for previous log groups
        for metric_filter in metric_filters:
            if metric_filter.log_group.name in log_groups and re.search(
                metric_filter_pattern, metric_filter.pattern, flags=re.DOTALL
            ):
                report = Check_Report_AWS(
                    metadata=metadata, resource=metric_filter.log_group
                )
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
