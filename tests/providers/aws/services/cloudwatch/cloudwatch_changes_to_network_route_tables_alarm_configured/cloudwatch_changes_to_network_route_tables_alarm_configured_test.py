from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_ARN,
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_cloudwatch_changes_to_network_route_tables_alarm_configured:
    @mock_aws
    @mock_aws
    def test_cloudwatch_no_log_groups(self):
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            CloudWatch,
            Logs,
        )

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        from prowler.providers.common.models import Audit_Metadata

        current_audit_info.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call __describe_log_groups__
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured.logs_client",
            new=Logs(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_client",
            new=CloudWatch(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured import (
                cloudwatch_changes_to_network_route_tables_alarm_configured,
            )

            check = cloudwatch_changes_to_network_route_tables_alarm_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No CloudWatch log groups found with metric filters or alarms associated."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == AWS_ACCOUNT_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    @mock_aws
    def test_cloudwatch_trail_no_log_group(self):
        cloudtrail_client = client("cloudtrail", region_name=AWS_REGION_US_EAST_1)
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        s3_client.create_bucket(Bucket="test")
        cloudtrail_client.create_trail(Name="test_trail", S3BucketName="test")

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            CloudWatch,
            Logs,
        )

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        from prowler.providers.common.models import Audit_Metadata

        current_audit_info.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call __describe_log_groups__
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured.logs_client",
            new=Logs(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_client",
            new=CloudWatch(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured import (
                cloudwatch_changes_to_network_route_tables_alarm_configured,
            )

            check = cloudwatch_changes_to_network_route_tables_alarm_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No CloudWatch log groups found with metric filters or alarms associated."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == AWS_ACCOUNT_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    @mock_aws
    def test_cloudwatch_trail_with_log_group(self):
        cloudtrail_client = client("cloudtrail", region_name=AWS_REGION_US_EAST_1)
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        s3_client.create_bucket(Bucket="test")
        logs_client.create_log_group(logGroupName="/log-group/test")
        cloudtrail_client.create_trail(
            Name="test_trail",
            S3BucketName="test",
            CloudWatchLogsLogGroupArn=f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*",
        )

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            CloudWatch,
            Logs,
        )

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        from prowler.providers.common.models import Audit_Metadata

        current_audit_info.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call __describe_log_groups__
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured.logs_client",
            new=Logs(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_client",
            new=CloudWatch(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured import (
                cloudwatch_changes_to_network_route_tables_alarm_configured,
            )

            check = cloudwatch_changes_to_network_route_tables_alarm_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No CloudWatch log groups found with metric filters or alarms associated."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == AWS_ACCOUNT_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    @mock_aws
    def test_cloudwatch_trail_with_log_group_with_metric(self):
        cloudtrail_client = client("cloudtrail", region_name=AWS_REGION_US_EAST_1)
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        s3_client.create_bucket(Bucket="test")
        logs_client.create_log_group(logGroupName="/log-group/test")
        cloudtrail_client.create_trail(
            Name="test_trail",
            S3BucketName="test",
            CloudWatchLogsLogGroupArn=f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*",
        )
        logs_client.put_metric_filter(
            logGroupName="/log-group/test",
            filterName="test-filter",
            filterPattern="{($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation)|| ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }",
            metricTransformations=[
                {
                    "metricName": "my-metric",
                    "metricNamespace": "my-namespace",
                    "metricValue": "$.value",
                }
            ],
        )

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            CloudWatch,
            Logs,
        )

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        from prowler.providers.common.models import Audit_Metadata

        current_audit_info.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call __describe_log_groups__
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured.logs_client",
            new=Logs(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_client",
            new=CloudWatch(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured import (
                cloudwatch_changes_to_network_route_tables_alarm_configured,
            )

            check = cloudwatch_changes_to_network_route_tables_alarm_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "CloudWatch log group /log-group/test found with metric filter test-filter but no alarms associated."
            )
            assert result[0].resource_id == "/log-group/test"
            assert (
                result[0].resource_arn
                == f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:metric-filter/test-filter"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    @mock_aws
    def test_cloudwatch_trail_with_log_group_with_metric_and_alarm(self):
        cloudtrail_client = client("cloudtrail", region_name=AWS_REGION_US_EAST_1)
        cloudwatch_client = client("cloudwatch", region_name=AWS_REGION_US_EAST_1)
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        s3_client.create_bucket(Bucket="test")
        logs_client.create_log_group(logGroupName="/log-group/test")
        cloudtrail_client.create_trail(
            Name="test_trail",
            S3BucketName="test",
            CloudWatchLogsLogGroupArn=f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*",
        )
        logs_client.put_metric_filter(
            logGroupName="/log-group/test",
            filterName="test-filter",
            filterPattern="{($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation)|| ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }",
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

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            CloudWatch,
            Logs,
        )

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        from prowler.providers.common.models import Audit_Metadata

        current_audit_info.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call __describe_log_groups__
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured.logs_client",
            new=Logs(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_client",
            new=CloudWatch(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured import (
                cloudwatch_changes_to_network_route_tables_alarm_configured,
            )

            check = cloudwatch_changes_to_network_route_tables_alarm_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "CloudWatch log group /log-group/test found with metric filter test-filter and alarms set."
            )
            assert result[0].resource_id == "/log-group/test"
            assert (
                result[0].resource_arn
                == f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:metric-filter/test-filter"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    @mock_aws
    def test_cloudwatch_trail_with_log_group_with_metric_and_alarm_with_quotes(self):
        cloudtrail_client = client("cloudtrail", region_name=AWS_REGION_US_EAST_1)
        cloudwatch_client = client("cloudwatch", region_name=AWS_REGION_US_EAST_1)
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        s3_client.create_bucket(Bucket="test")
        logs_client.create_log_group(logGroupName="/log-group/test")
        cloudtrail_client.create_trail(
            Name="test_trail",
            S3BucketName="test",
            CloudWatchLogsLogGroupArn=f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*",
        )
        logs_client.put_metric_filter(
            logGroupName="/log-group/test",
            filterName="test-filter",
            filterPattern='{($.eventName = "CreateRoute") || ($.eventName = "CreateRouteTable") || ($.eventName = "ReplaceRoute") || ($.eventName = "ReplaceRouteTableAssociation")|| ($.eventName = "DeleteRouteTable") || ($.eventName = "DeleteRoute") || ($.eventName = "DisassociateRouteTable") }',
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

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            CloudWatch,
            Logs,
        )

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        from prowler.providers.common.models import Audit_Metadata

        current_audit_info.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call __describe_log_groups__
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured.logs_client",
            new=Logs(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_client",
            new=CloudWatch(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured import (
                cloudwatch_changes_to_network_route_tables_alarm_configured,
            )

            check = cloudwatch_changes_to_network_route_tables_alarm_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "CloudWatch log group /log-group/test found with metric filter test-filter and alarms set."
            )
            assert result[0].resource_id == "/log-group/test"
            assert (
                result[0].resource_arn
                == f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:metric-filter/test-filter"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    @mock_aws
    def test_cloudwatch_trail_with_log_group_with_metric_and_alarm_with_newlines(self):
        cloudtrail_client = client("cloudtrail", region_name=AWS_REGION_US_EAST_1)
        cloudwatch_client = client("cloudwatch", region_name=AWS_REGION_US_EAST_1)
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        s3_client.create_bucket(Bucket="test")
        logs_client.create_log_group(logGroupName="/log-group/test")
        cloudtrail_client.create_trail(
            Name="test_trail",
            S3BucketName="test",
            CloudWatchLogsLogGroupArn=f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*",
        )
        logs_client.put_metric_filter(
            logGroupName="/log-group/test",
            filterName="test-filter",
            filterPattern='{($.eventName = "CreateRoute") ||\n ($.eventName = "CreateRouteTable") ||\n ($.eventName = "ReplaceRoute") ||\n ($.eventName = "ReplaceRouteTableAssociation")||\n ($.eventName = "DeleteRouteTable") ||\n ($.eventName = "DeleteRoute") ||\n ($.eventName = "DisassociateRouteTable") }',
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

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            CloudWatch,
            Logs,
        )

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        from prowler.providers.common.models import Audit_Metadata

        current_audit_info.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call __describe_log_groups__
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured.logs_client",
            new=Logs(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_client",
            new=CloudWatch(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_changes_to_network_route_tables_alarm_configured.cloudwatch_changes_to_network_route_tables_alarm_configured import (
                cloudwatch_changes_to_network_route_tables_alarm_configured,
            )

            check = cloudwatch_changes_to_network_route_tables_alarm_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "CloudWatch log group /log-group/test found with metric filter test-filter and alarms set."
            )
            assert result[0].resource_id == "/log-group/test"
            assert (
                result[0].resource_arn
                == f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:metric-filter/test-filter"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
