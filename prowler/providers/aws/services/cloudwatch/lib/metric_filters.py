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
        parts.append(rf"(?=.*\$\.eventName\s*=\s*.?{re.escape(name)}\b)")
    for field, operator, value in extra_clauses or []:
        if operator not in ("=", "!="):
            raise ValueError(f"unsupported operator {operator!r}; expected '=' or '!='")
        op = r"\s*!=\s*" if operator == "!=" else r"\s*=\s*"
        parts.append(rf"(?=.*\$\.{re.escape(field)}{op}.?{re.escape(value)})")
    return "".join(parts)


def check_cloudwatch_log_metric_filter(
    metric_filter_pattern: str,
    trails: list,
    metric_filters: list,
    metric_alarms: list,
    metadata: dict,
) -> Check_Report_AWS | None:
    """Report whether a trail's log group has a matching metric filter and an alarm.

    Only metric filters attached to a log group that a CloudTrail trail delivers to
    are considered, and only those whose own pattern matches
    ``metric_filter_pattern``. A filter whose log group was not retrieved is skipped
    rather than dereferenced. One compliant filter anywhere short-circuits to PASS;
    otherwise the last matching filter found without an alarm is returned as FAIL.

    Args:
        metric_filter_pattern: regex from ``build_metric_filter_pattern``, matched
            against each filter's pattern with ``re.DOTALL``.
        trails: CloudTrail trails keyed by ARN; only those with a log group count.
        metric_filters: CloudWatch Logs metric filters to evaluate.
        metric_alarms: CloudWatch alarms, matched to a filter by metric name and
            region, and by namespace when both sides expose one.
        metadata: check metadata for the emitted report.

    Returns:
        A ``Check_Report_AWS`` for the deciding log group, or ``None`` when no
        filter matched or an inventory was not collected.
    """
    report = None
    # 1. Iterate for CloudWatch Log Group in CloudTrail trails
    log_groups = []
    if trails is not None and metric_filters is not None and metric_alarms is not None:
        for trail in trails.values():
            if trail.log_group_arn:
                log_groups.append(trail.log_group_arn.split(":")[6])
        # 2. Describe metric filters for previous log groups
        for metric_filter in metric_filters:
            # A filter whose log group was not retrieved cannot be matched against
            # the trail log groups, so it cannot satisfy the requirement.
            if metric_filter.log_group is None:
                continue
            if metric_filter.log_group.name in log_groups and re.search(
                metric_filter_pattern, metric_filter.pattern, flags=re.DOTALL
            ):
                report = Check_Report_AWS(
                    metadata=metadata, resource=metric_filter.log_group
                )
                report.status = "FAIL"
                report.status_extended = f"CloudWatch log group {metric_filter.log_group.name} found with metric filter {metric_filter.name} but no alarms associated."
                # 3. Check if there is an alarm for the metric. The alarm must
                # watch the same metric name in the same region, and the same
                # namespace when both sides expose one — a same-named metric
                # in another namespace or region is a different metric.
                for alarm in metric_alarms:
                    if (
                        alarm.metric == metric_filter.metric
                        and alarm.region == metric_filter.region
                        and (
                            not metric_filter.metric_namespace
                            or not alarm.name_space
                            or alarm.name_space == metric_filter.metric_namespace
                        )
                    ):
                        report.status = "PASS"
                        report.status_extended = f"CloudWatch log group {metric_filter.log_group.name} found with metric filter {metric_filter.name} and alarms set."
                        break
                if report.status == "PASS":
                    break

    return report
