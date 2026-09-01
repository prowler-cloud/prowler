from pathlib import Path

import prowler
from prowler.lib.check.models import CheckMetadata
from prowler.providers.aws.services.cloudtrail.cloudtrail_service import Trail
from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
    LogGroup,
    MetricAlarm,
    MetricFilter,
)
from prowler.providers.aws.services.cloudwatch.lib.metric_filters import (
    check_cloudwatch_log_metric_filter,
)

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"

TRAIL_ARN = f"arn:aws:cloudtrail:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:trail/trail-test"
TRAIL_LOG_GROUP_NAME = "trail-log-group"
TRAIL_LOG_GROUP_ARN = (
    f"arn:aws:logs:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:log-group:{TRAIL_LOG_GROUP_NAME}:*"
)

# Matches the filter patterns built below, so a filter is only skipped because of
# its missing log group and never because the pattern failed to match.
PATTERN = r"\$\.eventName\s*=\s*.?PutBucketPolicy"
FILTER_PATTERN = "{ ($.eventName = PutBucketPolicy) }"
METRIC_NAME = "PutBucketPolicyCount"

METADATA = CheckMetadata.parse_file(
    Path(prowler.__file__).parent
    / "providers/aws/services/cloudwatch/cloudwatch_log_metric_filter_unauthorized_api_calls/cloudwatch_log_metric_filter_unauthorized_api_calls.metadata.json"
).json()


def _trails():
    """One trail delivering to TRAIL_LOG_GROUP_NAME, putting that log group in scope.

    Without a trail carrying a log group ARN the check has nothing to match filters
    against and returns None for any input, which would make every assertion below
    pass for the wrong reason.
    """
    return {TRAIL_ARN: Trail(region=AWS_REGION, log_group_arn=TRAIL_LOG_GROUP_ARN)}


def _trail_log_group():
    """The trail's log group as the CloudWatch service would have collected it."""
    return LogGroup(
        arn=TRAIL_LOG_GROUP_ARN,
        name=TRAIL_LOG_GROUP_NAME,
        retention_days=7,
        never_expire=False,
        region=AWS_REGION,
    )


def _metric_filter(name, log_group, metric=METRIC_NAME):
    """Build a metric filter whose pattern always matches PATTERN.

    Args:
        name: filter name, which the report echoes in status_extended.
        log_group: the collected LogGroup, or None to model a filter whose log
            group was never retrieved -- the input that used to raise.
        metric: metric name an alarm has to carry for the filter to be compliant.
    """
    return MetricFilter(
        arn=f"arn:aws:logs:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:metric-filter/{name}",
        name=name,
        metric=metric,
        pattern=FILTER_PATTERN,
        log_group=log_group,
        region=AWS_REGION,
    )


def _alarm(metric=METRIC_NAME):
    """Build an alarm on metric; a non-default name models an unrelated alarm.

    The check pairs alarms to filters by metric name alone, so passing a metric no
    filter uses is how a filter with no alarm of its own is expressed.
    """
    return MetricAlarm(
        arn=f"arn:aws:cloudwatch:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:alarm:{metric}-alarm",
        name=f"{metric}-alarm",
        metric=metric,
        name_space="CloudTrailMetrics",
        region=AWS_REGION,
        alarm_actions=[f"arn:aws:sns:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:topic-test"],
        actions_enabled=True,
    )


class Test_check_cloudwatch_log_metric_filter:
    def test_metric_filter_without_collected_log_group(self):
        """A metric filter whose log group was not retrieved must be skipped
        instead of raising AttributeError on the None log group."""
        report = check_cloudwatch_log_metric_filter(
            PATTERN,
            _trails(),
            [_metric_filter("orphan-filter", None)],
            [_alarm()],
            METADATA,
        )

        assert report is None

    def test_uncollected_log_group_does_not_mask_a_compliant_filter(self):
        """The skip must not abandon the remaining filters: a compliant filter
        listed after an uncollected one still has to be evaluated."""
        report = check_cloudwatch_log_metric_filter(
            PATTERN,
            _trails(),
            [
                _metric_filter("orphan-filter", None),
                _metric_filter("trail-filter", _trail_log_group()),
            ],
            [_alarm()],
            METADATA,
        )

        assert report is not None
        assert report.status == "PASS"
        assert (
            report.status_extended
            == f"CloudWatch log group {TRAIL_LOG_GROUP_NAME} found with metric filter trail-filter and alarms set."
        )
        assert report.resource_id == TRAIL_LOG_GROUP_NAME
        assert report.resource_arn == TRAIL_LOG_GROUP_ARN
        assert report.region == AWS_REGION

    def test_uncollected_log_group_does_not_mask_a_missing_alarm(self):
        """The skip must not turn a filter with no alarm into a pass."""
        report = check_cloudwatch_log_metric_filter(
            PATTERN,
            _trails(),
            [
                _metric_filter("orphan-filter", None),
                _metric_filter("trail-filter", _trail_log_group()),
            ],
            [_alarm(metric="UnrelatedMetric")],
            METADATA,
        )

        assert report is not None
        assert report.status == "FAIL"
        assert (
            report.status_extended
            == f"CloudWatch log group {TRAIL_LOG_GROUP_NAME} found with metric filter trail-filter but no alarms associated."
        )
