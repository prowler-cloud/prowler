from unittest.mock import patch

import botocore
import pytest
from boto3 import client
from botocore.exceptions import ClientError
from moto import mock_aws

from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
    CloudWatch,
    LogGroup,
    Logs,
    _watched_metric_ids,
)
from prowler.providers.aws.services.cloudwatch.lib.metric_filters import (
    build_metric_filter_pattern,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    mocked_api_response,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


@pytest.mark.parametrize(
    ("expression_queries", "expected"),
    [
        (
            [
                {"Id": "base", "Expression": "agent_calls", "ReturnData": False},
                {"Id": "alarm", "Expression": "base * 2", "ReturnData": True},
            ],
            {"agent_calls"},
        ),
        (
            [
                {
                    "Id": "alarm",
                    "Expression": 'SUM(METRICS("agent"))',
                    "ReturnData": True,
                }
            ],
            {"agent_calls"},
        ),
    ],
)
def test_watched_metric_ids(expression_queries, expected):
    metric_queries = [
        {"Id": "agent_calls", "MetricStat": {}, "ReturnData": False},
        {"Id": "requests", "MetricStat": {}, "ReturnData": False},
    ]

    assert _watched_metric_ids(metric_queries + expression_queries) == expected


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
        assert len(cloudwatch.all_metric_alarms) == 1
        assert (
            cloudwatch.metric_alarms[0].arn
            == f"arn:aws:cloudwatch:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:alarm:test"
        )
        assert cloudwatch.metric_alarms[0].name == "test"
        assert cloudwatch.metric_alarms[0].metric == "test_metric"
        assert cloudwatch.metric_alarms[0].name_space == "test_namespace"
        assert cloudwatch.metric_alarms[0].namespaces == ["test_namespace"]
        assert [
            (reference.namespace, reference.name)
            for reference in cloudwatch.metric_alarms[0].metric_references
        ] == [("test_namespace", "test_metric")]
        assert cloudwatch.metric_alarms[0].metric_references[0].dimensions == {
            "InstanceId": "i-0123457"
        }
        assert cloudwatch.metric_alarms[0].metric_references[0].account_id is None
        assert cloudwatch.metric_alarms[0].region == AWS_REGION_US_EAST_1
        assert cloudwatch.metric_alarms[0].tags == [
            {"Key": "key-1", "Value": "value-1"}
        ]
        assert cloudwatch.metric_alarms[0].alarm_actions == ["arn:alarm"]
        assert cloudwatch.metric_alarms[0].actions_enabled
        assert cloudwatch.metric_alarms_scanned_regions == {AWS_REGION_US_EAST_1}
        assert cloudwatch.metric_alarms_scan_errors == {}

    @mock_aws
    def test_describe_metric_math_alarm(self):
        cw_client = client("cloudwatch", region_name=AWS_REGION_US_EAST_1)
        cw_client.put_metric_alarm(
            AlarmName="agent-rate",
            ComparisonOperator="GreaterThanThreshold",
            EvaluationPeriods=1,
            Threshold=10,
            ActionsEnabled=True,
            Metrics=[
                {
                    "Id": "agent_calls",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/Bedrock/Agents",
                            "MetricName": "InvocationCount",
                            "Dimensions": [
                                {"Name": "Operation", "Value": "InvokeAgent"}
                            ],
                        },
                        "Period": 60,
                        "Stat": "Sum",
                    },
                    "ReturnData": False,
                },
                {
                    "Id": "requests",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "Custom/App",
                            "MetricName": "RequestCount",
                        },
                        "Period": 60,
                        "Stat": "Sum",
                    },
                    "ReturnData": False,
                },
                {
                    "Id": "rate",
                    "Expression": "agent_calls / requests",
                    "ReturnData": True,
                },
            ],
        )

        cloudwatch = CloudWatch(set_mocked_aws_provider())

        assert len(cloudwatch.metric_alarms) == 1
        alarm = cloudwatch.metric_alarms[0]
        assert alarm.metric is None
        assert alarm.name_space is None
        assert alarm.namespaces == ["AWS/Bedrock/Agents", "Custom/App"]
        assert [
            (reference.namespace, reference.name)
            for reference in alarm.metric_references
        ] == [
            ("AWS/Bedrock/Agents", "InvocationCount"),
            ("Custom/App", "RequestCount"),
        ]
        assert alarm.metric_references[0].dimensions == {"Operation": "InvokeAgent"}
        assert alarm.metric_references[0].account_id is None
        assert alarm.metric_references[1].dimensions == {}
        assert alarm.metric_references[1].account_id is None

    def test_describe_metric_math_alarm_keeps_account_id(self):
        class Paginator:
            def paginate(self):
                yield mocked_api_response(
                    "cloudwatch",
                    "DescribeAlarms",
                    {
                        "MetricAlarms": [
                            {
                                "AlarmArn": "arn:aws:cloudwatch:us-east-1:123456789012:alarm:cross-account",
                                "AlarmName": "cross-account",
                                "ActionsEnabled": True,
                                "Metrics": [
                                    {
                                        "Id": "agent_calls",
                                        "AccountId": AWS_ACCOUNT_NUMBER,
                                        "MetricStat": {
                                            "Metric": {
                                                "Namespace": "AWS/Bedrock/Agents",
                                                "MetricName": "InvocationCount",
                                                "Dimensions": [
                                                    {
                                                        "Name": "Operation",
                                                        "Value": "InvokeAgent",
                                                    }
                                                ],
                                            },
                                            "Period": 60,
                                            "Stat": "Sum",
                                        },
                                        "ReturnData": True,
                                    }
                                ],
                            }
                        ]
                    },
                )

        class CloudWatchClient:
            region = AWS_REGION_US_EAST_1

            def get_paginator(self, name):
                assert name == "describe_alarms"
                return Paginator()

        cloudwatch = CloudWatch.__new__(CloudWatch)
        cloudwatch.audit_resources = [
            "arn:aws:bedrock:us-east-1:123456789012:agent/agent-id"
        ]
        cloudwatch.metric_alarms = []
        cloudwatch.all_metric_alarms = []
        cloudwatch.metric_alarms_scanned_regions = set()
        cloudwatch.metric_alarms_scan_errors = {}

        cloudwatch._describe_alarms(CloudWatchClient())

        assert cloudwatch.metric_alarms == []
        reference = cloudwatch.all_metric_alarms[0].metric_references[0]
        assert reference.account_id == AWS_ACCOUNT_NUMBER

    @mock_aws
    def test_describe_metric_math_ignores_unused_metric(self):
        cw_client = client("cloudwatch", region_name=AWS_REGION_US_EAST_1)
        cw_client.put_metric_alarm(
            AlarmName="request-rate",
            ComparisonOperator="GreaterThanThreshold",
            EvaluationPeriods=1,
            Threshold=10,
            ActionsEnabled=True,
            Metrics=[
                {
                    "Id": "agent_calls",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/Bedrock/Agents",
                            "MetricName": "InvocationCount",
                            "Dimensions": [
                                {"Name": "Operation", "Value": "InvokeAgent"}
                            ],
                        },
                        "Period": 60,
                        "Stat": "Sum",
                    },
                    "ReturnData": False,
                },
                {
                    "Id": "requests",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "Custom/App",
                            "MetricName": "RequestCount",
                        },
                        "Period": 60,
                        "Stat": "Sum",
                    },
                    "ReturnData": False,
                },
                {
                    "Id": "rate",
                    "Expression": "requests",
                    "ReturnData": True,
                },
            ],
        )

        cloudwatch = CloudWatch(set_mocked_aws_provider())

        assert [
            (reference.namespace, reference.name)
            for reference in cloudwatch.metric_alarms[0].metric_references
        ] == [("Custom/App", "RequestCount")]

    def test_describe_alarms_keeps_partial_region_error(self):
        class PartialPaginator:
            def paginate(self):
                yield mocked_api_response(
                    "cloudwatch",
                    "DescribeAlarms",
                    {
                        "MetricAlarms": [
                            {
                                "AlarmArn": "arn:aws:cloudwatch:us-east-1:123456789012:alarm:partial",
                                "AlarmName": "partial",
                                "Namespace": "AWS/Bedrock/Agents",
                                "MetricName": "InvocationCount",
                                "ActionsEnabled": True,
                            }
                        ]
                    },
                )
                raise ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "denied"}},
                    "DescribeAlarms",
                )

        class PartialCloudWatchClient:
            region = AWS_REGION_US_EAST_1

            def get_paginator(self, name):
                assert name == "describe_alarms"
                return PartialPaginator()

        cloudwatch = CloudWatch.__new__(CloudWatch)
        cloudwatch.audit_resources = []
        cloudwatch.metric_alarms = []
        cloudwatch.all_metric_alarms = []
        cloudwatch.metric_alarms_scanned_regions = set()
        cloudwatch.metric_alarms_scan_errors = {}

        cloudwatch._describe_alarms(PartialCloudWatchClient())

        assert len(cloudwatch.metric_alarms) == 1
        assert cloudwatch.metric_alarms_scan_errors == {
            AWS_REGION_US_EAST_1: "AccessDenied"
        }
        assert cloudwatch.metric_alarms_scanned_regions == set()

    def test_describe_alarms_tracks_regions_independently(self):
        class Paginator:
            def __init__(self, error=None):
                self.error = error

            def paginate(self):
                if self.error:
                    raise self.error
                yield mocked_api_response(
                    "cloudwatch", "DescribeAlarms", {"MetricAlarms": []}
                )

        class CloudWatchClient:
            def __init__(self, region, error=None):
                self.region = region
                self.error = error

            def get_paginator(self, name):
                assert name == "describe_alarms"
                return Paginator(self.error)

        denied = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "DescribeAlarms",
        )
        cloudwatch = CloudWatch.__new__(CloudWatch)
        cloudwatch.audit_resources = []
        cloudwatch.metric_alarms = []
        cloudwatch.all_metric_alarms = []
        cloudwatch.metric_alarms_scanned_regions = set()
        cloudwatch.metric_alarms_scan_errors = {}

        cloudwatch._describe_alarms(CloudWatchClient(AWS_REGION_US_EAST_1, denied))
        cloudwatch._describe_alarms(CloudWatchClient(AWS_REGION_EU_WEST_1))

        assert cloudwatch.metric_alarms == []
        assert cloudwatch.metric_alarms_scan_errors == {
            AWS_REGION_US_EAST_1: "AccessDenied"
        }
        assert cloudwatch.metric_alarms_scanned_regions == {AWS_REGION_EU_WEST_1}

    @mock_aws
    def test_describe_alarms_access_denied_keeps_legacy_none(self):
        def deny_describe_alarms(self, operation_name, kwargs):
            if operation_name == "DescribeAlarms":
                raise ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "denied"}},
                    operation_name,
                )
            return make_api_call(self, operation_name, kwargs)

        provider = set_mocked_aws_provider(audited_regions=[AWS_REGION_US_EAST_1])
        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=deny_describe_alarms,
        ):
            cloudwatch = CloudWatch(provider)

        assert cloudwatch.metric_alarms is None
        assert cloudwatch.all_metric_alarms == []
        assert cloudwatch.metric_alarms_unavailable
        assert cloudwatch.metric_alarms_scan_errors == {
            AWS_REGION_US_EAST_1: "AccessDenied"
        }
        assert cloudwatch.metric_alarms_scanned_regions == set()

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
        assert logs.metric_filters[0].metric_namespace == "my-namespace"
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
        arn = f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*"
        logs = Logs(aws_provider)
        assert len(logs.log_groups) == 1
        assert len(logs.all_log_groups) == 1
        assert arn in logs.log_groups
        assert arn in logs.all_log_groups
        assert logs.log_groups[arn].name == "/log-group/test"
        assert logs.log_groups[arn].retention_days == 400
        assert logs.log_groups[arn].kms_id == "test_kms_id"
        assert not logs.log_groups[arn].never_expire
        assert logs.log_groups[arn].region == AWS_REGION_US_EAST_1
        assert logs.log_groups[arn].tags == [{}]

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
        arn = f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*"
        logs = Logs(aws_provider)
        assert len(logs.log_groups) == 1
        assert len(logs.all_log_groups) == 1
        assert arn in logs.log_groups
        assert arn in logs.all_log_groups
        assert logs.log_groups[arn].name == "/log-group/test"
        assert logs.log_groups[arn].never_expire
        # Since it never expires we don't use the retention_days
        assert logs.log_groups[arn].retention_days == 9999
        assert logs.log_groups[arn].kms_id == "test_kms_id"
        assert logs.log_groups[arn].region == AWS_REGION_US_EAST_1
        assert logs.log_groups[arn].tags == [{}]

    @mock_aws
    def test_describe_log_groups_data_protection_across_pages(self):
        """Both data protection fields must be collected from every page of DescribeLogGroups.

        moto has no data protection support, so the response is served literally. Both pages carry
        state a check reads, and each page carries a different one: a collector that stops after the
        first page under-reports silently instead of failing loudly. The second page also proves
        inheritedProperties survives the round trip rather than being flattened away.
        """
        first_page_arn = f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/aws/bedrock-agentcore/runtimes/page-one:*"
        second_page_arn = f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/aws/bedrock-agentcore/runtimes/page-two:*"
        pages = [
            {
                "logGroups": [
                    {
                        "arn": first_page_arn,
                        "logGroupName": "/aws/bedrock-agentcore/runtimes/page-one",
                        "creationTime": 2,
                        "dataProtectionStatus": "DISABLED",
                    }
                ],
                "nextToken": "page-two",
            },
            {
                "logGroups": [
                    {
                        "arn": second_page_arn,
                        "logGroupName": "/aws/bedrock-agentcore/runtimes/page-two",
                        "creationTime": 1,
                        "dataProtectionStatus": "ACTIVATED",
                        "inheritedProperties": ["ACCOUNT_DATA_PROTECTION"],
                    }
                ]
            },
        ]

        def mock_make_api_call(self, operation_name, kwarg):
            """Serve page two once the paginator follows nextToken, page one otherwise."""
            if operation_name == "DescribeLogGroups":
                return pages[1] if kwarg.get("nextToken") else pages[0]
            return make_api_call(self, operation_name, kwarg)

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1],
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
        )
        with patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call):
            logs = Logs(aws_provider)

        assert set(logs.log_groups) == {first_page_arn, second_page_arn}
        assert logs.log_groups[first_page_arn].data_protection_status == "DISABLED"
        assert logs.log_groups[first_page_arn].inherited_properties == []
        assert logs.log_groups[second_page_arn].data_protection_status == "ACTIVATED"
        assert logs.log_groups[second_page_arn].inherited_properties == [
            "ACCOUNT_DATA_PROTECTION"
        ]

    @mock_aws
    def test_describe_log_groups_without_data_protection_fields(self):
        """A log group reporting neither field must collect as None and an empty list.

        This is the common real response, since DescribeLogGroups omits both members for a log group
        that has never had a policy. None must not become "DISABLED" and the list must not become
        None, or a check cannot tell "never configured" from "switched off".
        """
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        logs_client.create_log_group(logGroupName="/log-group/test")

        aws_provider = set_mocked_aws_provider(
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"]
        )
        arn = f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*"
        logs = Logs(aws_provider)

        assert logs.log_groups[arn].data_protection_status is None
        assert logs.log_groups[arn].inherited_properties == []

    @mock_aws
    def test_describe_log_groups_access_denied_leaves_inventory_unknown(self):
        """A denied DescribeLogGroups must leave both indexes None, not empty dicts.

        None is the state checks read as "inventory unknown" and report MANUAL for. Collapsing to an
        empty dict would be indistinguishable from an account that has no log groups, which every
        log group check reads as nothing to report.
        """

        def mock_make_api_call(self, operation_name, kwarg):
            """Deny DescribeLogGroups; defer every other operation to botocore."""
            if operation_name == "DescribeLogGroups":
                raise ClientError(
                    {
                        "Error": {
                            "Code": "AccessDeniedException",
                            "Message": "not authorized",
                        }
                    },
                    operation_name,
                )
            return make_api_call(self, operation_name, kwarg)

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1],
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
        )
        with patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call):
            logs = Logs(aws_provider)

        assert logs.log_groups is None
        assert logs.all_log_groups is None

    def test_log_group_limit_exposes_only_selected_resources(self):
        class FakeLogsClient:
            def __init__(self):
                self.filter_calls = []

            def filter_log_events(self, **kwargs):
                self.filter_calls.append(kwargs["logGroupName"])
                return {"events": []}

        regional_client = FakeLogsClient()
        logs = Logs.__new__(Logs)
        logs.log_group_limit = 1
        logs._log_groups_hydrated = set()
        logs.regional_clients = {AWS_REGION_US_EAST_1: regional_client}
        logs.events_per_log_group_threshold = 1000
        logs.log_groups = {
            f"arn:{i}": LogGroup(
                arn=f"arn:{i}",
                name=f"log-{i}",
                retention_days=30,
                never_expire=False,
                kms_id=None,
                creation_time=i,
                region=AWS_REGION_US_EAST_1,
            )
            for i in range(3)
        }
        tagged = []

        def list_tags(log_group):
            tagged.append(log_group.arn)

        logs._list_tags_for_resource = list_tags

        logs._select_log_groups_for_analysis()
        for log_group in logs.log_groups.values():
            logs._list_tags_for_resource(log_group)
            logs._get_log_events(log_group)

        assert list(logs.log_groups) == ["arn:2"]
        assert tagged == ["arn:2"]
        assert regional_client.filter_calls == ["log-2"]

    def test_log_group_limit_selects_global_newest_across_regions(self):
        class FakePaginator:
            def __init__(self, log_groups):
                self.log_groups = log_groups

            def paginate(self, **kwargs):
                assert "PageSize" not in kwargs
                return [{"logGroups": self.log_groups}]

        class FakeLogsClient:
            def __init__(self, region, log_groups):
                self.region = region
                self.log_groups = log_groups

            def get_paginator(self, name):
                assert name == "describe_log_groups"
                return FakePaginator(self.log_groups)

        logs = Logs.__new__(Logs)
        logs.all_log_groups = {}
        logs.log_groups = {}
        logs.log_group_limit = 1
        logs.audit_resources = []

        logs._describe_log_groups(
            FakeLogsClient(
                "eu-west-1",
                [
                    {
                        "arn": "arn:aws:logs:eu-west-1:123456789012:log-group:old:*",
                        "logGroupName": "old",
                        "creationTime": 1,
                    }
                ],
            )
        )
        logs._describe_log_groups(
            FakeLogsClient(
                AWS_REGION_US_EAST_1,
                [
                    {
                        "arn": "arn:aws:logs:us-east-1:123456789012:log-group:new:*",
                        "logGroupName": "new",
                        "creationTime": 2,
                    }
                ],
            )
        )
        logs._select_log_groups_for_analysis()

        assert [log_group.name for log_group in logs.log_groups.values()] == ["new"]
        assert [log_group.name for log_group in logs.all_log_groups.values()] == [
            "old",
            "new",
        ]

    def test_metric_filters_use_complete_log_group_index(self):
        class FakePaginator:
            def paginate(self):
                return [
                    {
                        "metricFilters": [
                            {
                                "filterName": "test-filter",
                                "filterPattern": "test-pattern",
                                "logGroupName": "old",
                                "metricTransformations": [
                                    {"metricName": "test-metric"}
                                ],
                            }
                        ]
                    }
                ]

        class FakeLogsClient:
            region = AWS_REGION_US_EAST_1

            def get_paginator(self, name):
                assert name == "describe_metric_filters"
                return FakePaginator()

        logs = Logs.__new__(Logs)
        old_log_group = LogGroup(
            arn="arn:old",
            name="old",
            retention_days=30,
            never_expire=False,
            kms_id=None,
            creation_time=1,
            region=AWS_REGION_US_EAST_1,
        )
        logs.audited_partition = "aws"
        logs.audited_account = AWS_ACCOUNT_NUMBER
        logs.audit_resources = []
        logs.metric_filters = []
        logs.log_groups = {}
        logs.all_log_groups = {old_log_group.arn: old_log_group}
        logs._log_groups_hydrated = set()
        logs._list_tags_for_resource = lambda log_group: None

        logs._describe_metric_filters(FakeLogsClient())

        assert len(logs.metric_filters) == 1
        assert logs.metric_filters[0].log_group == old_log_group

    def test_log_group_collection_recovers_all_log_groups_after_access_denied(self):
        class FakePaginator:
            def paginate(self):
                return [
                    {
                        "logGroups": [
                            {
                                "arn": "arn:aws:logs:us-east-1:123456789012:log-group:success:*",
                                "logGroupName": "success",
                                "creationTime": 1,
                            }
                        ]
                    }
                ]

        class FakeLogsClient:
            region = AWS_REGION_US_EAST_1

            def get_paginator(self, name):
                assert name == "describe_log_groups"
                return FakePaginator()

        logs = Logs.__new__(Logs)
        logs.all_log_groups = None
        logs.log_groups = None
        logs.audit_resources = []

        logs._describe_log_groups(FakeLogsClient())

        assert list(logs.all_log_groups) == [
            "arn:aws:logs:us-east-1:123456789012:log-group:success:*"
        ]
        assert list(logs.log_groups) == [
            "arn:aws:logs:us-east-1:123456789012:log-group:success:*"
        ]


class Test_build_metric_filter_pattern:
    @pytest.mark.parametrize("bad_operator", ["==", "~=", "<", "<>", ">=", ""])
    def test_rejects_unsupported_operator(self, bad_operator):
        with pytest.raises(ValueError, match="unsupported operator"):
            build_metric_filter_pattern(
                event_names=["ConsoleLogin"],
                extra_clauses=[("errorMessage", bad_operator, "Failed authentication")],
            )

    @mock_aws
    def test_describe_log_groups_access_denied_sets_flag(self):
        """A denied DescribeLogGroups must raise log_groups_unavailable."""
        from unittest import mock

        from botocore.client import BaseClient
        from botocore.exceptions import ClientError

        orig = BaseClient._make_api_call

        def deny_describe_log_groups(self, operation_name, kwarg):
            if operation_name == "DescribeLogGroups":
                raise ClientError(
                    {
                        "Error": {
                            "Code": "AccessDeniedException",
                            "Message": "Access Denied",
                        }
                    },
                    operation_name,
                )
            return orig(self, operation_name, kwarg)

        aws_provider = set_mocked_aws_provider(
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"]
        )
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=deny_describe_log_groups,
        ):
            logs = Logs(aws_provider)

        assert logs.log_groups_unavailable is True
        assert logs.log_groups is None
        assert logs.all_log_groups is None
