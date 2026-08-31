import pathlib

from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
    LogGroup,
    MetricAlarm,
    MetricFilter,
)
from prowler.providers.aws.services.cloudwatch.lib.metric_filters import (
    check_cloudwatch_log_metric_filter,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1

PATTERN = r"root"
# Real metadata is required to build the Check_Report_AWS inside the helper.
METADATA = (
    pathlib.Path(__file__).parents[6]
    / "prowler"
    / "providers"
    / "aws"
    / "services"
    / "cloudwatch"
    / "cloudwatch_log_metric_filter_root_usage"
    / "cloudwatch_log_metric_filter_root_usage.metadata.json"
).read_text()


class Trail:
    def __init__(self, log_group_arn):
        self.log_group_arn = log_group_arn


def _log_group(name="/log-group/test", region=AWS_REGION_US_EAST_1):
    return LogGroup(
        arn=f"arn:aws:logs:{region}:{AWS_ACCOUNT_NUMBER}:log-group:{name}:*",
        name=name,
        retention_days=365,
        never_expire=False,
        kms_id=None,
        region=region,
    )


def _trail(log_group_name="/log-group/test", region=AWS_REGION_US_EAST_1):
    return Trail(
        f"arn:aws:logs:{region}:{AWS_ACCOUNT_NUMBER}:log-group:{log_group_name}:*"
    )


def _metric_filter(
    metric="my-metric",
    namespace="my-namespace",
    log_group=None,
    region=AWS_REGION_US_EAST_1,
):
    return MetricFilter(
        arn=f"arn:aws:logs:{region}:{AWS_ACCOUNT_NUMBER}:metric-filter/test-filter",
        name="test-filter",
        metric=metric,
        metric_namespace=namespace,
        pattern="root",
        log_group=log_group,
        region=region,
    )


def _alarm(metric="my-metric", namespace="my-namespace", region=AWS_REGION_US_EAST_1):
    return MetricAlarm(
        arn=f"arn:aws:cloudwatch:{region}:{AWS_ACCOUNT_NUMBER}:alarm:test-alarm",
        name="test-alarm",
        metric=metric,
        name_space=namespace,
        region=region,
        alarm_actions=[],
        actions_enabled=True,
    )


class TestCheckCloudwatchLogMetricFilter:
    def test_filter_without_log_group_is_skipped_not_crash(self):
        """DescribeLogGroups denied -> MetricFilter(log_group=None): no AttributeError."""
        report = check_cloudwatch_log_metric_filter(
            PATTERN,
            {"t": _trail()},
            [_metric_filter(log_group=None)],
            [_alarm()],
            METADATA,
        )
        assert report is None

    def test_alarm_in_other_namespace_does_not_pass(self):
        report = check_cloudwatch_log_metric_filter(
            PATTERN,
            {"t": _trail()},
            [_metric_filter(log_group=_log_group())],
            [_alarm(namespace="other-namespace")],
            METADATA,
        )
        assert report.status == "FAIL"
        assert "no alarms associated" in report.status_extended

    def test_alarm_in_other_region_does_not_pass(self):
        report = check_cloudwatch_log_metric_filter(
            PATTERN,
            {"t": _trail()},
            [_metric_filter(log_group=_log_group())],
            [_alarm(region="eu-west-1")],
            METADATA,
        )
        assert report.status == "FAIL"

    def test_alarm_matching_metric_namespace_and_region_passes(self):
        report = check_cloudwatch_log_metric_filter(
            PATTERN,
            {"t": _trail()},
            [_metric_filter(log_group=_log_group())],
            [_alarm()],
            METADATA,
        )
        assert report.status == "PASS"

    def test_alarm_without_namespace_still_matches(self):
        """Namespace is only compared when both sides expose one."""
        report = check_cloudwatch_log_metric_filter(
            PATTERN,
            {"t": _trail()},
            [_metric_filter(log_group=_log_group())],
            [_alarm(namespace=None)],
            METADATA,
        )
        assert report.status == "PASS"
