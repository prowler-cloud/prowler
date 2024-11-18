from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
    CloudWatch,
    Logs,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_CloudWatch_Service:
    # Test CloudWatch Service
    @mock_aws
    def test_service(self):
        # CloudWatch client for this test class
        aws_provider = set_mocked_aws_provider(
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"]
        )
        cloudwatch = CloudWatch(aws_provider)
        assert cloudwatch.service == "cloudwatch"

    # Test CloudWatch Client
    @mock_aws
    def test_client(self):
        # CloudWatch client for this test class
        aws_provider = set_mocked_aws_provider(
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"]
        )
        cloudwatch = CloudWatch(aws_provider)
        for client_ in cloudwatch.regional_clients.values():
            assert client_.__class__.__name__ == "CloudWatch"

    # Test CloudWatch Session
    @mock_aws
    def test__get_session__(self):
        # CloudWatch client for this test class
        aws_provider = set_mocked_aws_provider(
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"]
        )
        cloudwatch = CloudWatch(aws_provider)
        assert cloudwatch.session.__class__.__name__ == "Session"

    # Test CloudWatch Session
    @mock_aws
    def test_audited_account(self):
        # CloudWatch client for this test class
        aws_provider = set_mocked_aws_provider(
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"]
        )
        cloudwatch = CloudWatch(aws_provider)
        assert cloudwatch.audited_account == AWS_ACCOUNT_NUMBER

    # Test Logs Service
    @mock_aws
    def test_logs_service(self):
        # Logs client for this test class
        aws_provider = set_mocked_aws_provider(
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"]
        )
        logs = Logs(aws_provider)
        assert logs.service == "logs"

    # Test Logs Client
    @mock_aws
    def test_logs_client(self):
        # Logs client for this test class
        aws_provider = set_mocked_aws_provider(
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"]
        )
        logs = Logs(aws_provider)
        for client_ in logs.regional_clients.values():
            assert client_.__class__.__name__ == "CloudWatchLogs"

    # Test Logs Session
    @mock_aws
    def test__logs_get_session__(self):
        # Logs client for this test class
        aws_provider = set_mocked_aws_provider(
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"]
        )
        logs = Logs(aws_provider)
        assert logs.session.__class__.__name__ == "Session"

    # Test Logs Session
    @mock_aws
    def test_logs_audited_account(self):
        # Logs client for this test class
        aws_provider = set_mocked_aws_provider(
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"]
        )
        logs = Logs(aws_provider)
        assert logs.audited_account == AWS_ACCOUNT_NUMBER

    # Test CloudWatch Alarms
    @mock_aws
    def test_describe_alarms(self):
        # CloudWatch client for this test class
        cw_client = client("cloudwatch", region_name=AWS_REGION_US_EAST_1)
        cw_client.put_metric_alarm(
            AlarmActions=["arn:alarm"],
            AlarmDescription="A test",
            AlarmName="test",
            ComparisonOperator="GreaterThanOrEqualToThreshold",
            Dimensions=[{"Name": "InstanceId", "Value": "i-0123457"}],
            EvaluationPeriods=5,
            InsufficientDataActions=["arn:insufficient"],
            Namespace="test_namespace",
            MetricName="test_metric",
            OKActions=["arn:ok"],
            Period=60,
            Statistic="Average",
            Threshold=2,
            Unit="Seconds",
            Tags=[{"Key": "key-1", "Value": "value-1"}],
            ActionsEnabled=True,
        )
        aws_provider = set_mocked_aws_provider(
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"]
        )
        cloudwatch = CloudWatch(aws_provider)
        assert len(cloudwatch.metric_alarms) == 1
        assert (
            cloudwatch.metric_alarms[0].arn
            == f"arn:aws:cloudwatch:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:alarm:test"
        )
        assert cloudwatch.metric_alarms[0].name == "test"
        assert cloudwatch.metric_alarms[0].metric == "test_metric"
        assert cloudwatch.metric_alarms[0].name_space == "test_namespace"
        assert cloudwatch.metric_alarms[0].region == AWS_REGION_US_EAST_1
        assert cloudwatch.metric_alarms[0].tags == [
            {"Key": "key-1", "Value": "value-1"}
        ]
        assert cloudwatch.metric_alarms[0].alarm_actions == ["arn:alarm"]
        assert cloudwatch.metric_alarms[0].actions_enabled

    # Test Logs Filters
    @mock_aws
    def test_describe_metric_filters(self):
        # Logs client for this test class
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        logs_client.put_metric_filter(
            logGroupName="/log-group/test",
            filterName="test-filter",
            filterPattern="test-pattern",
            metricTransformations=[
                {
                    "metricName": "my-metric",
                    "metricNamespace": "my-namespace",
                    "metricValue": "$.value",
                }
            ],
        )
        aws_provider = set_mocked_aws_provider(
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"]
        )
        logs = Logs(aws_provider)
        assert len(logs.metric_filters) == 1
        assert logs.metric_filters[0].log_group is None
        assert logs.metric_filters[0].name == "test-filter"
        assert logs.metric_filters[0].metric == "my-metric"
        assert logs.metric_filters[0].pattern == "test-pattern"
        assert logs.metric_filters[0].region == AWS_REGION_US_EAST_1

    # Test Logs Filters
    @mock_aws
    def test_describe_log_groups(self):
        # Logs client for this test class
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        logs_client.create_log_group(
            logGroupName="/log-group/test",
            kmsKeyId="test_kms_id",
            tags={"tag_key_1": "tag_value_1", "tag_key_2": "tag_value_2"},
        )
        logs_client.put_retention_policy(
            logGroupName="/log-group/test", retentionInDays=400
        )
        aws_provider = set_mocked_aws_provider(
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"]
        )
        arn = f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test"
        logs = Logs(aws_provider)
        assert len(logs.log_groups) == 1
        assert arn in logs.log_groups
        assert logs.log_groups[arn].name == "/log-group/test"
        assert logs.log_groups[arn].retention_days == 400
        assert logs.log_groups[arn].kms_id == "test_kms_id"
        assert not logs.log_groups[arn].never_expire
        assert logs.log_groups[arn].region == AWS_REGION_US_EAST_1
        assert logs.log_groups[arn].tags == [
            {"tag_key_1": "tag_value_1", "tag_key_2": "tag_value_2"}
        ]

    @mock_aws
    def test_describe_log_groupsnever_expire(self):
        # Logs client for this test class
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        logs_client.create_log_group(
            logGroupName="/log-group/test",
            kmsKeyId="test_kms_id",
            tags={"tag_key_1": "tag_value_1", "tag_key_2": "tag_value_2"},
        )

        aws_provider = set_mocked_aws_provider(
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"]
        )
        arn = f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test"
        logs = Logs(aws_provider)
        assert len(logs.log_groups) == 1
        assert arn in logs.log_groups
        assert logs.log_groups[arn].name == "/log-group/test"
        assert logs.log_groups[arn].never_expire
        # Since it never expires we don't use the retention_days
        assert logs.log_groups[arn].retention_days == 9999
        assert logs.log_groups[arn].kms_id == "test_kms_id"
        assert logs.log_groups[arn].region == AWS_REGION_US_EAST_1
        assert logs.log_groups[arn].tags == [
            {"tag_key_1": "tag_value_1", "tag_key_2": "tag_value_2"}
        ]
