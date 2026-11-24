from pathlib import Path

import pytest

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
TRAIL_LOG_GROUP_ARN_WITHOUT_SUFFIX = (
    f"arn:aws:logs:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:log-group:{TRAIL_LOG_GROUP_NAME}"
)
FOREIGN_REGION = "us-east-1"
FOREIGN_ACCOUNT_NUMBER = "999999999999"
FOREIGN_REGION_LOG_GROUP_ARN = f"arn:aws:logs:{FOREIGN_REGION}:{AWS_ACCOUNT_NUMBER}:log-group:{TRAIL_LOG_GROUP_NAME}:*"
FOREIGN_ACCOUNT_LOG_GROUP_ARN = f"arn:aws:logs:{AWS_REGION}:{FOREIGN_ACCOUNT_NUMBER}:log-group:{TRAIL_LOG_GROUP_NAME}:*"

# Matches the filter patterns built below, so a filter is only skipped because of
# its missing log group and never because the pattern failed to match.
PATTERN = r"\$\.eventName\s*=\s*.?PutBucketPolicy"
FILTER_PATTERN = "{ ($.eventName = PutBucketPolicy) }"
METRIC_NAME = "PutBucketPolicyCount"

METADATA = CheckMetadata.parse_file(
    Path(prowler.__file__).parent
    / "providers/aws/services/cloudwatch/cloudwatch_log_metric_filter_unauthorized_api_calls/cloudwatch_log_metric_filter_unauthorized_api_calls.metadata.json"
).json()


def _trails(log_group_arn=TRAIL_LOG_GROUP_ARN):
    """One trail delivering to TRAIL_LOG_GROUP_NAME, putting that log group in scope.

    Without a trail carrying a log group ARN the check has nothing to match filters
    against and returns None for any input, which would make every assertion below
    pass for the wrong reason.
    """
    return {TRAIL_ARN: Trail(region=AWS_REGION, log_group_arn=log_group_arn)}


def _trail_log_group(arn=TRAIL_LOG_GROUP_ARN, region=AWS_REGION):
    """The trail's log group as the CloudWatch service would have collected it."""
    return LogGroup(
        arn=arn,
        name=TRAIL_LOG_GROUP_NAME,
        retention_days=7,
        never_expire=False,
        region=region,
    )


def _metric_filter(
    name,
    log_group,
    metric=METRIC_NAME,
    namespace="CloudTrailMetrics",
    region=AWS_REGION,
    account=AWS_ACCOUNT_NUMBER,
):
    """Build a metric filter whose pattern always matches PATTERN.

    Args:
        name: filter name, which the report echoes in status_extended.
        log_group: the collected LogGroup, or None to model a filter whose log
            group was never retrieved -- the input that used to raise.
        metric: metric name an alarm has to carry for the filter to be compliant.
        namespace: metric namespace the filter publishes to, or None when the
            transformation does not expose one.
        region: region of the collected metric filter.
        account: account of the collected metric filter.
    """
    return MetricFilter(
        arn=f"arn:aws:logs:{region}:{account}:metric-filter/{name}",
        name=name,
        metric=metric,
        metric_namespace=namespace,
        pattern=FILTER_PATTERN,
        log_group=log_group,
        region=region,
    )


def _alarm(
    metric=METRIC_NAME,
    namespace="CloudTrailMetrics",
    region=AWS_REGION,
    account=AWS_ACCOUNT_NUMBER,
):
    """Build an alarm on metric; a non-default name models an unrelated alarm.

    The check pairs alarms to filters by metric name and region (and namespace
    when both sides expose one), so passing a metric no filter uses is how a
    filter with no alarm of its own is expressed.
    """
    return MetricAlarm(
        arn=f"arn:aws:cloudwatch:{region}:{account}:alarm:{metric}-alarm",
        name=f"{metric}-alarm",
        metric=metric,
        name_space=namespace,
        region=region,
        alarm_actions=[f"arn:aws:sns:{region}:{account}:topic-test"],
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

    def test_alarm_in_other_namespace_does_not_pass(self):
        """A same-named metric in another namespace is a different metric."""
        report = check_cloudwatch_log_metric_filter(
            PATTERN,
            _trails(),
            [_metric_filter("trail-filter", _trail_log_group())],
            [_alarm(namespace="OtherNamespace")],
            METADATA,
        )

        assert report.status == "FAIL"
        assert "no alarms associated" in report.status_extended

    def test_alarm_in_other_region_does_not_pass(self):
        """A same-named metric in another region is a different metric."""
        report = check_cloudwatch_log_metric_filter(
            PATTERN,
            _trails(),
            [_metric_filter("trail-filter", _trail_log_group())],
            [_alarm(region="us-east-1")],
            METADATA,
        )

        assert report.status == "FAIL"

    def test_alarm_without_namespace_still_matches(self):
        """Namespace is only compared when both sides expose one."""
        report = check_cloudwatch_log_metric_filter(
            PATTERN,
            _trails(),
            [_metric_filter("trail-filter", _trail_log_group())],
            [_alarm(namespace=None)],
            METADATA,
        )

        assert report.status == "PASS"

    def test_filter_without_namespace_still_matches(self):
        """A filter with no namespace accepts an alarm in any namespace."""
        report = check_cloudwatch_log_metric_filter(
            PATTERN,
            _trails(),
            [_metric_filter("trail-filter", _trail_log_group(), namespace=None)],
            [_alarm()],
            METADATA,
        )

        assert report.status == "PASS"

    def test_same_name_foreign_region_log_group_is_ignored(self):
        """A same-named log group in another region is not the trail destination.

        The foreign log group, its filter, and its alarm are all collected in the
        same region so only the trail destination identity distinguishes them.
        """
        foreign_group = _trail_log_group(
            arn=FOREIGN_REGION_LOG_GROUP_ARN, region=FOREIGN_REGION
        )
        report = check_cloudwatch_log_metric_filter(
            PATTERN,
            _trails(),
            [
                _metric_filter(
                    "foreign-region-filter", foreign_group, region=FOREIGN_REGION
                )
            ],
            [_alarm(region=FOREIGN_REGION)],
            METADATA,
        )

        assert report is None

    def test_same_name_foreign_account_log_group_is_ignored(self):
        """A same-named log group in another account is not the trail destination.

        This is a model-boundary identity assertion only; cross-account collection
        by the scanner is not claimed here.
        """
        foreign_group = _trail_log_group(arn=FOREIGN_ACCOUNT_LOG_GROUP_ARN)
        report = check_cloudwatch_log_metric_filter(
            PATTERN,
            _trails(),
            [
                _metric_filter(
                    "foreign-account-filter",
                    foreign_group,
                    account=FOREIGN_ACCOUNT_NUMBER,
                )
            ],
            [_alarm(account=FOREIGN_ACCOUNT_NUMBER)],
            METADATA,
        )

        assert report is None

    def test_exact_destination_identity_passes(self):
        """The collected log group at the trail destination satisfies the check."""
        report = check_cloudwatch_log_metric_filter(
            PATTERN,
            _trails(),
            [_metric_filter("destination-filter", _trail_log_group())],
            [_alarm()],
            METADATA,
        )

        assert report is not None
        assert report.status == "PASS"
        assert "destination-filter" in report.status_extended
        assert report.resource_arn == TRAIL_LOG_GROUP_ARN
        assert report.region == AWS_REGION

    @pytest.mark.parametrize(
        ("trail_log_group_arn", "collected_log_group_arn"),
        [
            (TRAIL_LOG_GROUP_ARN, TRAIL_LOG_GROUP_ARN_WITHOUT_SUFFIX),
            (TRAIL_LOG_GROUP_ARN_WITHOUT_SUFFIX, TRAIL_LOG_GROUP_ARN),
        ],
    )
    def test_equivalent_destination_arns_with_optional_suffix_pass(
        self, trail_log_group_arn, collected_log_group_arn
    ):
        """The API-equivalent terminal ':*' form must not change identity."""
        report = check_cloudwatch_log_metric_filter(
            PATTERN,
            _trails(log_group_arn=trail_log_group_arn),
            [
                _metric_filter(
                    "suffix-filter",
                    _trail_log_group(arn=collected_log_group_arn),
                )
            ],
            [_alarm()],
            METADATA,
        )

        assert report is not None
        assert report.status == "PASS"
        assert report.resource_arn == collected_log_group_arn
        assert report.region == AWS_REGION

    def test_foreign_filter_does_not_mask_valid_destination_report(self):
        """A foreign same-name PASS must not hide the actual destination report."""
        foreign_group = _trail_log_group(
            arn=FOREIGN_REGION_LOG_GROUP_ARN, region=FOREIGN_REGION
        )
        report = check_cloudwatch_log_metric_filter(
            PATTERN,
            _trails(),
            [
                _metric_filter(
                    "foreign-region-filter", foreign_group, region=FOREIGN_REGION
                ),
                _metric_filter("destination-filter", _trail_log_group()),
            ],
            [_alarm(region=FOREIGN_REGION), _alarm()],
            METADATA,
        )

        assert report is not None
        assert report.status == "PASS"
        assert "destination-filter" in report.status_extended
        assert report.resource_arn == TRAIL_LOG_GROUP_ARN
        assert report.region == AWS_REGION
