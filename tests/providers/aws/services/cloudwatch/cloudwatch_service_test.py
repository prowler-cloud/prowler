from boto3 import client, session
from moto import mock_cloudwatch, mock_logs

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
    CloudWatch,
    Logs,
)
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


class Test_CloudWatch_Service:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                # We need to set this check to call __describe_log_groups__
                expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        return audit_info

    # Test CloudWatch Service
    @mock_cloudwatch
    def test_service(self):
        # CloudWatch client for this test class
        audit_info = self.set_mocked_audit_info()
        cloudwatch = CloudWatch(audit_info)
        assert cloudwatch.service == "cloudwatch"

    # Test CloudWatch Client
    @mock_cloudwatch
    def test_client(self):
        # CloudWatch client for this test class
        audit_info = self.set_mocked_audit_info()
        cloudwatch = CloudWatch(audit_info)
        for client_ in cloudwatch.regional_clients.values():
            assert client_.__class__.__name__ == "CloudWatch"

    # Test CloudWatch Session
    @mock_cloudwatch
    def test__get_session__(self):
        # CloudWatch client for this test class
        audit_info = self.set_mocked_audit_info()
        cloudwatch = CloudWatch(audit_info)
        assert cloudwatch.session.__class__.__name__ == "Session"

    # Test CloudWatch Session
    @mock_cloudwatch
    def test_audited_account(self):
        # CloudWatch client for this test class
        audit_info = self.set_mocked_audit_info()
        cloudwatch = CloudWatch(audit_info)
        assert cloudwatch.audited_account == AWS_ACCOUNT_NUMBER

    # Test Logs Service
    @mock_logs
    def test_logs_service(self):
        # Logs client for this test class
        audit_info = self.set_mocked_audit_info()
        logs = Logs(audit_info)
        assert logs.service == "logs"

    # Test Logs Client
    @mock_logs
    def test_logs_client(self):
        # Logs client for this test class
        audit_info = self.set_mocked_audit_info()
        logs = Logs(audit_info)
        for client_ in logs.regional_clients.values():
            assert client_.__class__.__name__ == "CloudWatchLogs"

    # Test Logs Session
    @mock_logs
    def test__logs_get_session__(self):
        # Logs client for this test class
        audit_info = self.set_mocked_audit_info()
        logs = Logs(audit_info)
        assert logs.session.__class__.__name__ == "Session"

    # Test Logs Session
    @mock_logs
    def test_logs_audited_account(self):
        # Logs client for this test class
        audit_info = self.set_mocked_audit_info()
        logs = Logs(audit_info)
        assert logs.audited_account == AWS_ACCOUNT_NUMBER

    # Test CloudWatch Alarms
    @mock_cloudwatch
    def test__describe_alarms__(self):
        # CloudWatch client for this test class
        cw_client = client("cloudwatch", region_name=AWS_REGION)
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
        )
        audit_info = self.set_mocked_audit_info()
        cloudwatch = CloudWatch(audit_info)
        assert len(cloudwatch.metric_alarms) == 1
        assert (
            cloudwatch.metric_alarms[0].arn
            == f"arn:aws:cloudwatch:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:alarm:test"
        )
        assert cloudwatch.metric_alarms[0].name == "test"
        assert cloudwatch.metric_alarms[0].metric == "test_metric"
        assert cloudwatch.metric_alarms[0].name_space == "test_namespace"
        assert cloudwatch.metric_alarms[0].region == AWS_REGION
        assert cloudwatch.metric_alarms[0].tags == [
            {"Key": "key-1", "Value": "value-1"}
        ]

    # Test Logs Filters
    @mock_logs
    def test__describe_metric_filters__(self):
        # Logs client for this test class
        logs_client = client("logs", region_name=AWS_REGION)
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
        audit_info = self.set_mocked_audit_info()
        logs = Logs(audit_info)
        assert len(logs.metric_filters) == 1
        assert logs.metric_filters[0].log_group == "/log-group/test"
        assert logs.metric_filters[0].name == "test-filter"
        assert logs.metric_filters[0].metric == "my-metric"
        assert logs.metric_filters[0].pattern == "test-pattern"
        assert logs.metric_filters[0].region == AWS_REGION

    # Test Logs Filters
    @mock_logs
    def test__describe_log_groups__(self):
        # Logs client for this test class
        logs_client = client("logs", region_name=AWS_REGION)
        logs_client.create_log_group(
            logGroupName="/log-group/test",
            kmsKeyId="test_kms_id",
            tags={"tag_key_1": "tag_value_1", "tag_key_2": "tag_value_2"},
        )
        logs_client.put_retention_policy(
            logGroupName="/log-group/test", retentionInDays=400
        )
        audit_info = self.set_mocked_audit_info()
        logs = Logs(audit_info)
        assert len(logs.log_groups) == 1
        assert (
            logs.log_groups[0].arn
            == f"arn:aws:logs:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test"
        )
        assert logs.log_groups[0].name == "/log-group/test"
        assert logs.log_groups[0].retention_days == 400
        assert logs.log_groups[0].kms_id == "test_kms_id"
        assert logs.log_groups[0].region == AWS_REGION
        assert logs.log_groups[0].tags == [
            {"tag_key_1": "tag_value_1", "tag_key_2": "tag_value_2"}
        ]
