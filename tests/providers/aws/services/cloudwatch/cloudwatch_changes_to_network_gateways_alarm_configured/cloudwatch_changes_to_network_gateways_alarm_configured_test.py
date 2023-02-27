from unittest import mock

from boto3 import client
from moto import mock_cloudtrail, mock_cloudwatch, mock_logs, mock_s3
from moto.core import DEFAULT_ACCOUNT_ID

AWS_REGION = "us-east-1"


class Test_cloudwatch_log_metric_filter_unauthorized_api_calls:
    @mock_logs
    @mock_cloudtrail
    @mock_cloudwatch
    def test_cloudwatch_no_log_groups(self):
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            CloudWatch,
            Logs,
        )

        current_audit_info.audited_partition = "aws"
        from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
            Cloudtrail,
        )

        with mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured.logs_client",
            new=Logs(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_client",
            new=CloudWatch(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured import (
                cloudwatch_changes_to_network_gateways_alarm_configured,
            )

            check = cloudwatch_changes_to_network_gateways_alarm_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No CloudWatch log groups found with metric filters or alarms associated."
            )
            assert result[0].resource_id == current_audit_info.audited_account

    @mock_logs
    @mock_cloudtrail
    @mock_cloudwatch
    @mock_s3
    def test_cloudwatch_trail_no_log_group(self):
        cloudtrail_client = client("cloudtrail", region_name=AWS_REGION)
        s3_client = client("s3", region_name=AWS_REGION)
        s3_client.create_bucket(Bucket="test")
        cloudtrail_client.create_trail(Name="test_trail", S3BucketName="test")

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            CloudWatch,
            Logs,
        )

        current_audit_info.audited_partition = "aws"
        from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
            Cloudtrail,
        )

        with mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured.logs_client",
            new=Logs(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_client",
            new=CloudWatch(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured import (
                cloudwatch_changes_to_network_gateways_alarm_configured,
            )

            check = cloudwatch_changes_to_network_gateways_alarm_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No CloudWatch log groups found with metric filters or alarms associated."
            )
            assert result[0].resource_id == current_audit_info.audited_account

    @mock_logs
    @mock_cloudtrail
    @mock_cloudwatch
    @mock_s3
    def test_cloudwatch_trail_with_log_group(self):
        cloudtrail_client = client("cloudtrail", region_name=AWS_REGION)
        logs_client = client("logs", region_name=AWS_REGION)
        s3_client = client("s3", region_name=AWS_REGION)
        s3_client.create_bucket(Bucket="test")
        logs_client.create_log_group(logGroupName="/log-group/test")
        cloudtrail_client.create_trail(
            Name="test_trail",
            S3BucketName="test",
            CloudWatchLogsLogGroupArn=f"arn:aws:logs:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:log-group:/log-group/test:*",
        )

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            CloudWatch,
            Logs,
        )

        current_audit_info.audited_partition = "aws"
        from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
            Cloudtrail,
        )

        with mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured.logs_client",
            new=Logs(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_client",
            new=CloudWatch(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured import (
                cloudwatch_changes_to_network_gateways_alarm_configured,
            )

            check = cloudwatch_changes_to_network_gateways_alarm_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No CloudWatch log groups found with metric filters or alarms associated."
            )
            assert result[0].resource_id == current_audit_info.audited_account

    @mock_logs
    @mock_cloudtrail
    @mock_cloudwatch
    @mock_s3
    def test_cloudwatch_trail_with_log_group_with_metric(self):
        cloudtrail_client = client("cloudtrail", region_name=AWS_REGION)
        logs_client = client("logs", region_name=AWS_REGION)
        s3_client = client("s3", region_name=AWS_REGION)
        s3_client.create_bucket(Bucket="test")
        logs_client.create_log_group(logGroupName="/log-group/test")
        cloudtrail_client.create_trail(
            Name="test_trail",
            S3BucketName="test",
            CloudWatchLogsLogGroupArn=f"arn:aws:logs:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:log-group:/log-group/test:*",
        )
        logs_client.put_metric_filter(
            logGroupName="/log-group/test",
            filterName="test-filter",
            filterPattern="{($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) ||  ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }",
            metricTransformations=[
                {
                    "metricName": "my-metric",
                    "metricNamespace": "my-namespace",
                    "metricValue": "$.value",
                }
            ],
        )

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            CloudWatch,
            Logs,
        )

        current_audit_info.audited_partition = "aws"
        from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
            Cloudtrail,
        )

        with mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured.logs_client",
            new=Logs(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_client",
            new=CloudWatch(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured import (
                cloudwatch_changes_to_network_gateways_alarm_configured,
            )

            check = cloudwatch_changes_to_network_gateways_alarm_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "CloudWatch log group /log-group/test found with metric filter test-filter but no alarms associated."
            )
            assert result[0].resource_id == "/log-group/test"

    @mock_logs
    @mock_cloudtrail
    @mock_cloudwatch
    @mock_s3
    def test_cloudwatch_trail_with_log_group_with_metric_and_alarm(self):
        cloudtrail_client = client("cloudtrail", region_name=AWS_REGION)
        cloudwatch_client = client("cloudwatch", region_name=AWS_REGION)
        logs_client = client("logs", region_name=AWS_REGION)
        s3_client = client("s3", region_name=AWS_REGION)
        s3_client.create_bucket(Bucket="test")
        logs_client.create_log_group(logGroupName="/log-group/test")
        cloudtrail_client.create_trail(
            Name="test_trail",
            S3BucketName="test",
            CloudWatchLogsLogGroupArn=f"arn:aws:logs:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:log-group:/log-group/test:*",
        )
        logs_client.put_metric_filter(
            logGroupName="/log-group/test",
            filterName="test-filter",
            filterPattern="{($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) ||  ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }",
            metricTransformations=[
                {
                    "metricName": "my-metric",
                    "metricNamespace": "my-namespace",
                    "metricValue": "$.value",
                }
            ],
        )
        cloudwatch_client.put_metric_alarm(
            AlarmName="test-alarm",
            MetricName="my-metric",
            Namespace="my-namespace",
            Period=10,
            EvaluationPeriods=5,
            Statistic="Average",
            Threshold=2,
            ComparisonOperator="GreaterThanThreshold",
            ActionsEnabled=True,
        )

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            CloudWatch,
            Logs,
        )

        current_audit_info.audited_partition = "aws"
        from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
            Cloudtrail,
        )

        with mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured.logs_client",
            new=Logs(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_client",
            new=CloudWatch(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured import (
                cloudwatch_changes_to_network_gateways_alarm_configured,
            )

            check = cloudwatch_changes_to_network_gateways_alarm_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "CloudWatch log group /log-group/test found with metric filter test-filter and alarms set."
            )
            assert result[0].resource_id == "/log-group/test"

    @mock_logs
    @mock_cloudtrail
    @mock_cloudwatch
    @mock_s3
    def test_cloudwatch_trail_with_log_group_with_metric_and_alarm_with_quotes(self):
        cloudtrail_client = client("cloudtrail", region_name=AWS_REGION)
        cloudwatch_client = client("cloudwatch", region_name=AWS_REGION)
        logs_client = client("logs", region_name=AWS_REGION)
        s3_client = client("s3", region_name=AWS_REGION)
        s3_client.create_bucket(Bucket="test")
        logs_client.create_log_group(logGroupName="/log-group/test")
        cloudtrail_client.create_trail(
            Name="test_trail",
            S3BucketName="test",
            CloudWatchLogsLogGroupArn=f"arn:aws:logs:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:log-group:/log-group/test:*",
        )
        logs_client.put_metric_filter(
            logGroupName="/log-group/test",
            filterName="test-filter",
            filterPattern='{($.eventName = "CreateCustomerGateway") || ($.eventName = "DeleteCustomerGateway") || ($.eventName = "AttachInternetGateway") || ($.eventName = "CreateInternetGateway") ||  ($.eventName = "DeleteInternetGateway") || ($.eventName = "DetachInternetGateway") }',
            metricTransformations=[
                {
                    "metricName": "my-metric",
                    "metricNamespace": "my-namespace",
                    "metricValue": "$.value",
                }
            ],
        )
        cloudwatch_client.put_metric_alarm(
            AlarmName="test-alarm",
            MetricName="my-metric",
            Namespace="my-namespace",
            Period=10,
            EvaluationPeriods=5,
            Statistic="Average",
            Threshold=2,
            ComparisonOperator="GreaterThanThreshold",
            ActionsEnabled=True,
        )

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            CloudWatch,
            Logs,
        )

        current_audit_info.audited_partition = "aws"
        from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
            Cloudtrail,
        )

        with mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured.logs_client",
            new=Logs(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_client",
            new=CloudWatch(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_gateways_alarm_configured.cloudwatch_changes_to_network_gateways_alarm_configured import (
                cloudwatch_changes_to_network_gateways_alarm_configured,
            )

            check = cloudwatch_changes_to_network_gateways_alarm_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "CloudWatch log group /log-group/test found with metric filter test-filter and alarms set."
            )
            assert result[0].resource_id == "/log-group/test"
