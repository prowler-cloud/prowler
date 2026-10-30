from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_cloudwatch_log_metric_filter_unauthorized_api_calls:
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.logs_client",
                new=Logs(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_client",
                new=CloudWatch(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls import (
                cloudwatch_log_metric_filter_unauthorized_api_calls,
            )

            check = cloudwatch_log_metric_filter_unauthorized_api_calls()
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.logs_client",
                new=Logs(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_client",
                new=CloudWatch(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls import (
                cloudwatch_log_metric_filter_unauthorized_api_calls,
            )

            check = cloudwatch_log_metric_filter_unauthorized_api_calls()
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
            CloudWatchLogsLogGroupArn=f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*",
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.logs_client",
                new=Logs(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_client",
                new=CloudWatch(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls import (
                cloudwatch_log_metric_filter_unauthorized_api_calls,
            )

            check = cloudwatch_log_metric_filter_unauthorized_api_calls()
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
            CloudWatchLogsLogGroupArn=f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*",
        )
        logs_client.put_metric_filter(
            logGroupName="/log-group/test",
            filterName="test-filter",
            filterPattern="{ ($.errorCode = *UnauthorizedOperation) || ($.errorCode = AccessDenied*) || ($.sourceIPAddress!=delivery.logs.amazonaws.com) || ($.eventName!=HeadBucket) }",
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.logs_client",
                new=Logs(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_client",
                new=CloudWatch(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls import (
                cloudwatch_log_metric_filter_unauthorized_api_calls,
            )

            check = cloudwatch_log_metric_filter_unauthorized_api_calls()
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
                == f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*"
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
            CloudWatchLogsLogGroupArn=f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*",
        )
        logs_client.put_metric_filter(
            logGroupName="/log-group/test",
            filterName="test-filter",
            filterPattern="{ ($.errorCode = *UnauthorizedOperation) || ($.errorCode = AccessDenied*) || ($.sourceIPAddress!=delivery.logs.amazonaws.com) || ($.eventName!=HeadBucket) }",
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.logs_client",
                new=Logs(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_client",
                new=CloudWatch(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls import (
                cloudwatch_log_metric_filter_unauthorized_api_calls,
            )

            check = cloudwatch_log_metric_filter_unauthorized_api_calls()
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
                == f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*"
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
            CloudWatchLogsLogGroupArn=f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*",
        )
        logs_client.put_metric_filter(
            logGroupName="/log-group/test",
            filterName="test-filter",
            filterPattern='{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") || ($.sourceIPAddress!="delivery.logs.amazonaws.com") || ($.eventName!="HeadBucket") }',
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.logs_client",
                new=Logs(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_client",
                new=CloudWatch(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls import (
                cloudwatch_log_metric_filter_unauthorized_api_calls,
            )

            check = cloudwatch_log_metric_filter_unauthorized_api_calls()
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
                == f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*"
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
            CloudWatchLogsLogGroupArn=f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*",
        )
        logs_client.put_metric_filter(
            logGroupName="/log-group/test",
            filterName="test-filter",
            filterPattern='{ ($.errorCode = "*UnauthorizedOperation") ||\n ($.errorCode = "AccessDenied*") ||\n ($.sourceIPAddress!="delivery.logs.amazonaws.com") ||\n ($.eventName!="HeadBucket") }',
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.logs_client",
                new=Logs(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_client",
                new=CloudWatch(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls import (
                cloudwatch_log_metric_filter_unauthorized_api_calls,
            )

            check = cloudwatch_log_metric_filter_unauthorized_api_calls()
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
                == f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    def _run_cross_region_same_name_case(self, place_filter_in_destination):
        """Run the real collectors and consumer for a two-region fixture.

        The trail home region and its destination log group are eu-west-1. A
        same-named log group exists in us-east-1, where a metric filter and its
        alarm can be placed. The destination group has no filter when the flag
        is false, so a PASS in that case can only come from the foreign group.
        """
        destination_arn = f"arn:aws:logs:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*"
        foreign_arn = f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*"

        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        s3_client.create_bucket(Bucket="test")

        cloudtrail = client("cloudtrail", region_name=AWS_REGION_EU_WEST_1)
        logs_eu_west_1 = client("logs", region_name=AWS_REGION_EU_WEST_1)
        logs_us_east_1 = client("logs", region_name=AWS_REGION_US_EAST_1)
        logs_eu_west_1.create_log_group(logGroupName="/log-group/test")
        logs_us_east_1.create_log_group(logGroupName="/log-group/test")
        cloudtrail.create_trail(
            Name="test_trail",
            S3BucketName="test",
            CloudWatchLogsLogGroupArn=destination_arn,
        )

        if place_filter_in_destination:
            filter_logs_client = logs_eu_west_1
            filter_region = AWS_REGION_EU_WEST_1
        else:
            filter_logs_client = logs_us_east_1
            filter_region = AWS_REGION_US_EAST_1
        filter_logs_client.put_metric_filter(
            logGroupName="/log-group/test",
            filterName="test-filter",
            filterPattern="{ ($.errorCode = *UnauthorizedOperation) || ($.errorCode = AccessDenied*) || ($.sourceIPAddress!=delivery.logs.amazonaws.com) || ($.eventName!=HeadBucket) }",
            metricTransformations=[
                {
                    "metricName": "my-metric",
                    "metricNamespace": "my-namespace",
                    "metricValue": "$.value",
                }
            ],
        )
        alarm_client = client("cloudwatch", region_name=filter_region)
        alarm_client.put_metric_alarm(
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

        logs_service = Logs(aws_provider)
        cloudwatch_service = CloudWatch(aws_provider)
        cloudtrail_service = Cloudtrail(aws_provider)

        trail = next(
            trail for trail in cloudtrail_service.trails.values() if trail.log_group_arn
        )
        assert trail.home_region == AWS_REGION_EU_WEST_1
        assert trail.log_group_arn == destination_arn

        collected_groups = list(logs_service.all_log_groups.values())
        assert any(
            group.arn == destination_arn and group.region == AWS_REGION_EU_WEST_1
            for group in collected_groups
        )
        assert any(
            group.arn == foreign_arn and group.region == AWS_REGION_US_EAST_1
            for group in collected_groups
        )

        collected_filters = [
            metric_filter
            for metric_filter in logs_service.metric_filters
            if metric_filter.name == "test-filter"
        ]
        assert len(collected_filters) == 1
        assert collected_filters[0].region == filter_region
        assert collected_filters[0].log_group.region == filter_region
        if place_filter_in_destination:
            assert collected_filters[0].log_group.arn == destination_arn
        else:
            assert collected_filters[0].log_group.arn == foreign_arn

        assert len(cloudwatch_service.metric_alarms) == 1
        assert cloudwatch_service.metric_alarms[0].region == filter_region

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.logs_client",
                new=logs_service,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_client",
                new=cloudwatch_service,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudtrail_client",
                new=cloudtrail_service,
            ),
        ):
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_unauthorized_api_calls.cloudwatch_log_metric_filter_unauthorized_api_calls import (
                cloudwatch_log_metric_filter_unauthorized_api_calls,
            )

            return cloudwatch_log_metric_filter_unauthorized_api_calls().execute()

    @mock_aws
    def test_same_name_foreign_region_filter_does_not_satisfy_trail(self):
        """A filter in a same-named foreign-region group is not trail coverage."""
        result = self._run_cross_region_same_name_case(
            place_filter_in_destination=False
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No CloudWatch log groups found with metric filters or alarms associated."
        )
        assert result[0].resource_id == AWS_ACCOUNT_NUMBER

    @mock_aws
    def test_destination_filter_and_alarm_satisfy_trail(self):
        """The positive control keeps the real destination association valid."""
        result = self._run_cross_region_same_name_case(place_filter_in_destination=True)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "CloudWatch log group /log-group/test found with metric filter test-filter and alarms set."
        )
        assert result[0].resource_id == "/log-group/test"
        assert (
            result[0].resource_arn
            == f"arn:aws:logs:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*"
        )
        assert result[0].region == AWS_REGION_EU_WEST_1
