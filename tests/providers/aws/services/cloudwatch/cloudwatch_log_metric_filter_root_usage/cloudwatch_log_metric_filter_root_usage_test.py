from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_cloudwatch_log_metric_filter_root_usage:
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
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.logs_client",
                new=Logs(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudwatch_client",
                new=CloudWatch(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage import (
                cloudwatch_log_metric_filter_root_usage,
            )

            check = cloudwatch_log_metric_filter_root_usage()
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
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.logs_client",
                new=Logs(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudwatch_client",
                new=CloudWatch(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage import (
                cloudwatch_log_metric_filter_root_usage,
            )

            check = cloudwatch_log_metric_filter_root_usage()
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.logs_client",
                new=Logs(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudwatch_client",
                new=CloudWatch(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage import (
                cloudwatch_log_metric_filter_root_usage,
            )

            check = cloudwatch_log_metric_filter_root_usage()
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
            filterPattern="{ $.userIdentity.type = Root && $.userIdentity.invokedBy NOT EXISTS && $.eventType != AwsServiceEvent }",
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
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.logs_client",
                new=Logs(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudwatch_client",
                new=CloudWatch(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage import (
                cloudwatch_log_metric_filter_root_usage,
            )

            check = cloudwatch_log_metric_filter_root_usage()
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
            CloudWatchLogsLogGroupArn=f"arn:aws:logs:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*",
        )
        logs_client.put_metric_filter(
            logGroupName="/log-group/test",
            filterName="test-filter",
            filterPattern="{ $.userIdentity.type = Root && $.userIdentity.invokedBy NOT EXISTS && $.eventType != AwsServiceEvent }",
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
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.logs_client",
                new=Logs(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudwatch_client",
                new=CloudWatch(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage import (
                cloudwatch_log_metric_filter_root_usage,
            )

            check = cloudwatch_log_metric_filter_root_usage()
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
            CloudWatchLogsLogGroupArn=f"arn:aws:logs:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*",
        )
        logs_client.put_metric_filter(
            logGroupName="/log-group/test",
            filterName="test-filter",
            filterPattern='{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }',
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
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.logs_client",
                new=Logs(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudwatch_client",
                new=CloudWatch(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage import (
                cloudwatch_log_metric_filter_root_usage,
            )

            check = cloudwatch_log_metric_filter_root_usage()
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
            CloudWatchLogsLogGroupArn=f"arn:aws:logs:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:log-group:/log-group/test:*",
        )
        logs_client.put_metric_filter(
            logGroupName="/log-group/test",
            filterName="test-filter",
            filterPattern='{ $.userIdentity.type = "Root" &&\n $.userIdentity.invokedBy NOT EXISTS &&\n $.eventType != "AwsServiceEvent" }',
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
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.logs_client",
                new=Logs(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudwatch_client",
                new=CloudWatch(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage import (
                cloudwatch_log_metric_filter_root_usage,
            )

            check = cloudwatch_log_metric_filter_root_usage()
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

    def _run_with_unavailable_data(self, *, metric_filters_none, metric_alarms_none):
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
        logs = Logs(aws_provider)
        cloudwatch = CloudWatch(aws_provider)
        # The services set these to None when the describe call is denied
        # (AccessDeniedException / AccessDenied).
        if metric_filters_none:
            logs.metric_filters = None
            logs.metric_filters_unavailable = True
        if metric_alarms_none:
            cloudwatch.metric_alarms = None
            cloudwatch.metric_alarms_unavailable = True

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.logs_client",
                new=logs,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudwatch_client",
                new=cloudwatch,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage import (
                cloudwatch_log_metric_filter_root_usage,
            )

            return cloudwatch_log_metric_filter_root_usage().execute()

    @mock_aws
    def test_cloudwatch_metric_filters_access_denied(self):
        """logs:DescribeMetricFilters denied -> MANUAL, not FAIL."""
        result = self._run_with_unavailable_data(
            metric_filters_none=True, metric_alarms_none=False
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            "metric filters or alarms could not be listed" in result[0].status_extended
        )
        assert "logs:DescribeMetricFilters" in result[0].status_extended
        assert result[0].resource_id == AWS_ACCOUNT_NUMBER
        assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_cloudwatch_metric_filters_partially_denied(self):
        """Filters listed in one region but denied in another -> MANUAL.

        The service keeps the partial list (not None) and only raises the
        ``metric_filters_unavailable`` flag; with no matching filter the check
        must not claim FAIL.
        """
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
        logs = Logs(aws_provider)
        assert logs.metric_filters == []
        logs.metric_filters_unavailable = True

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.logs_client",
                new=logs,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudwatch_client",
                new=CloudWatch(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage import (
                cloudwatch_log_metric_filter_root_usage,
            )

            result = cloudwatch_log_metric_filter_root_usage().execute()

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "in at least one region" in result[0].status_extended

    @mock_aws
    def test_cloudwatch_trails_access_denied(self):
        """cloudtrail:DescribeTrails denied -> MANUAL instead of no finding."""
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
        cloudtrail = Cloudtrail(aws_provider)
        cloudtrail.trails = None
        cloudtrail.trails_unavailable = True

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.logs_client",
                new=Logs(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudwatch_client",
                new=CloudWatch(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudtrail_client",
                new=cloudtrail,
            ),
        ):
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage import (
                cloudwatch_log_metric_filter_root_usage,
            )

            result = cloudwatch_log_metric_filter_root_usage().execute()

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "cloudtrail:DescribeTrails" in result[0].status_extended

    @mock_aws
    def test_cloudwatch_log_groups_access_denied(self):
        """logs:DescribeLogGroups denied -> MANUAL."""
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
        logs = Logs(aws_provider)
        logs.log_groups_unavailable = True

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.logs_client",
                new=logs,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudwatch_client",
                new=CloudWatch(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage import (
                cloudwatch_log_metric_filter_root_usage,
            )

            result = cloudwatch_log_metric_filter_root_usage().execute()

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "logs:DescribeLogGroups" in result[0].status_extended

    @mock_aws
    def test_cloudwatch_metric_alarms_access_denied(self):
        """cloudwatch:DescribeAlarms denied -> MANUAL, not FAIL."""
        result = self._run_with_unavailable_data(
            metric_filters_none=False, metric_alarms_none=True
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "cloudwatch:DescribeAlarms" in result[0].status_extended

    def _run_with_filter(self, *, with_alarm, metric_alarms_unavailable):
        """Create a trail + matching filter (optionally its alarm) and run the check
        with the alarm inventory flagged as (un)available."""
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
            filterPattern="{ $.userIdentity.type = Root && $.userIdentity.invokedBy NOT EXISTS && $.eventType != AwsServiceEvent }",
            metricTransformations=[
                {
                    "metricName": "my-metric",
                    "metricNamespace": "my-namespace",
                    "metricValue": "$.value",
                }
            ],
        )
        if with_alarm:
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
        from prowler.providers.common.models import Audit_Metadata

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        aws_provider.audit_metadata = Audit_Metadata(
            services_scanned=0,
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )
        cloudwatch = CloudWatch(aws_provider)
        cloudwatch.metric_alarms_unavailable = metric_alarms_unavailable

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.logs_client",
                new=Logs(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudwatch_client",
                new=cloudwatch,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_root_usage.cloudwatch_log_metric_filter_root_usage import (
                cloudwatch_log_metric_filter_root_usage,
            )

            return cloudwatch_log_metric_filter_root_usage().execute()

    @mock_aws
    def test_cloudwatch_match_found_despite_partial_denial_is_pass(self):
        """A filter with its alarm found in a readable region is real evidence:
        PASS even if another region denied the alarm listing."""
        result = self._run_with_filter(with_alarm=True, metric_alarms_unavailable=True)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == "/log-group/test"

    @mock_aws
    def test_cloudwatch_filter_without_alarm_under_partial_denial_is_manual(self):
        """Filter found but no alarm, while the alarm listing was denied in some
        region: the missing alarm cannot be asserted -> MANUAL, not FAIL."""
        result = self._run_with_filter(with_alarm=False, metric_alarms_unavailable=True)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "cloudwatch:DescribeAlarms" in result[0].status_extended

    @mock_aws
    def test_cloudwatch_filter_without_alarm_fully_listed_is_fail(self):
        """Same setup with a complete alarm inventory stays FAIL."""
        result = self._run_with_filter(
            with_alarm=False, metric_alarms_unavailable=False
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "no alarms associated" in result[0].status_extended
