from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_cloudwatch_log_metric_filter_sign_in_without_mfa:
    @mock_aws
    def test_cloudwatch_no_log_groups(self):
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            CloudWatch,
            Logs,
        )

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        from prowler.providers.common.models import Audit_Metadata

        aws_provider.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call _describe_log_groups
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa.logs_client",
            new=Logs(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_client",
            new=CloudWatch(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudtrail_client",
            new=Cloudtrail(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa import (
                cloudwatch_log_metric_filter_sign_in_without_mfa,
            )

            check = cloudwatch_log_metric_filter_sign_in_without_mfa()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No CloudWatch log groups found with metric filters or alarms associated."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:logs:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:log-group"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1

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

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        from prowler.providers.common.models import Audit_Metadata

        aws_provider.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call _describe_log_groups
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa.logs_client",
            new=Logs(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_client",
            new=CloudWatch(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudtrail_client",
            new=Cloudtrail(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa import (
                cloudwatch_log_metric_filter_sign_in_without_mfa,
            )

            check = cloudwatch_log_metric_filter_sign_in_without_mfa()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No CloudWatch log groups found with metric filters or alarms associated."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:logs:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:log-group"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1

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
            CloudWatchLogsLogGroupArn=f"arn:aws:logs:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*",
        )

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            CloudWatch,
            Logs,
        )

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        from prowler.providers.common.models import Audit_Metadata

        aws_provider.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call _describe_log_groups
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa.logs_client",
            new=Logs(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_client",
            new=CloudWatch(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudtrail_client",
            new=Cloudtrail(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa import (
                cloudwatch_log_metric_filter_sign_in_without_mfa,
            )

            check = cloudwatch_log_metric_filter_sign_in_without_mfa()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No CloudWatch log groups found with metric filters or alarms associated."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:logs:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:log-group"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1

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
            CloudWatchLogsLogGroupArn=f"arn:aws:logs:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*",
        )
        logs_client.put_metric_filter(
            logGroupName="/log-group/test",
            filterName="test-filter",
            filterPattern="{ ($.eventName = ConsoleLogin) && ($.additionalEventData.MFAUsed != Yes) }",
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

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        from prowler.providers.common.models import Audit_Metadata

        aws_provider.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call _describe_log_groups
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa.logs_client",
            new=Logs(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_client",
            new=CloudWatch(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudtrail_client",
            new=Cloudtrail(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa import (
                cloudwatch_log_metric_filter_sign_in_without_mfa,
            )

            check = cloudwatch_log_metric_filter_sign_in_without_mfa()
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
                == f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

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
            CloudWatchLogsLogGroupArn=f"arn:aws:logs:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*",
        )
        logs_client.put_metric_filter(
            logGroupName="/log-group/test",
            filterName="test-filter",
            filterPattern="{ ($.eventName = ConsoleLogin) && ($.additionalEventData.MFAUsed != Yes) }",
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

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        from prowler.providers.common.models import Audit_Metadata

        aws_provider.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call _describe_log_groups
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa.logs_client",
            new=Logs(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_client",
            new=CloudWatch(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudtrail_client",
            new=Cloudtrail(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa import (
                cloudwatch_log_metric_filter_sign_in_without_mfa,
            )

            check = cloudwatch_log_metric_filter_sign_in_without_mfa()
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
                == f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

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
            CloudWatchLogsLogGroupArn=f"arn:aws:logs:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*",
        )
        logs_client.put_metric_filter(
            logGroupName="/log-group/test",
            filterName="test-filter",
            filterPattern='{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }',
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

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        from prowler.providers.common.models import Audit_Metadata

        aws_provider.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call _describe_log_groups
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa.logs_client",
            new=Logs(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_client",
            new=CloudWatch(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudtrail_client",
            new=Cloudtrail(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa import (
                cloudwatch_log_metric_filter_sign_in_without_mfa,
            )

            check = cloudwatch_log_metric_filter_sign_in_without_mfa()
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
                == f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

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
            CloudWatchLogsLogGroupArn=f"arn:aws:logs:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*",
        )
        logs_client.put_metric_filter(
            logGroupName="/log-group/test",
            filterName="test-filter",
            filterPattern="{ ($.eventName = ConsoleLogin) &&\n ($.additionalEventData.MFAUsed != Yes) }",
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

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        from prowler.providers.common.models import Audit_Metadata

        aws_provider.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call _describe_log_groups
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa.logs_client",
            new=Logs(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_client",
            new=CloudWatch(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudtrail_client",
            new=Cloudtrail(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_sign_in_without_mfa.cloudwatch_log_metric_filter_sign_in_without_mfa import (
                cloudwatch_log_metric_filter_sign_in_without_mfa,
            )

            check = cloudwatch_log_metric_filter_sign_in_without_mfa()
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
                == f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
