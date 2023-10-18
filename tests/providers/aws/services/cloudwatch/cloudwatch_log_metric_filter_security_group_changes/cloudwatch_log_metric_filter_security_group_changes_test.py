from unittest import mock

from boto3 import client, session
from moto import mock_cloudtrail, mock_cloudwatch, mock_logs, mock_s3
from moto.core import DEFAULT_ACCOUNT_ID

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_REGION = "us-east-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_cloudwatch_log_metric_filter_unauthorized_api_calls:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=["us-east-1", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )

        return audit_info

    @mock_logs
    @mock_cloudtrail
    @mock_cloudwatch
    def test_cloudwatch_no_log_groups(self):
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            CloudWatch,
            Logs,
        )

        current_audit_info = self.set_mocked_audit_info()

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
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes.logs_client",
            new=Logs(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_client",
            new=CloudWatch(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes import (
                cloudwatch_log_metric_filter_security_group_changes,
            )

            check = cloudwatch_log_metric_filter_security_group_changes()
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

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            CloudWatch,
            Logs,
        )

        current_audit_info = self.set_mocked_audit_info()

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
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes.logs_client",
            new=Logs(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_client",
            new=CloudWatch(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes import (
                cloudwatch_log_metric_filter_security_group_changes,
            )

            check = cloudwatch_log_metric_filter_security_group_changes()
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

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            CloudWatch,
            Logs,
        )

        current_audit_info = self.set_mocked_audit_info()

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
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes.logs_client",
            new=Logs(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_client",
            new=CloudWatch(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes import (
                cloudwatch_log_metric_filter_security_group_changes,
            )

            check = cloudwatch_log_metric_filter_security_group_changes()
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
            filterPattern="{($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }",
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

        current_audit_info = self.set_mocked_audit_info()

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
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes.logs_client",
            new=Logs(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_client",
            new=CloudWatch(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes import (
                cloudwatch_log_metric_filter_security_group_changes,
            )

            check = cloudwatch_log_metric_filter_security_group_changes()
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
            filterPattern="{($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }",
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

        current_audit_info = self.set_mocked_audit_info()

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
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes.logs_client",
            new=Logs(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_client",
            new=CloudWatch(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes import (
                cloudwatch_log_metric_filter_security_group_changes,
            )

            check = cloudwatch_log_metric_filter_security_group_changes()
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
            filterPattern='{($.eventName = "AuthorizeSecurityGroupIngress") || ($.eventName = "AuthorizeSecurityGroupEgress") || ($.eventName = "RevokeSecurityGroupIngress") || ($.eventName = "RevokeSecurityGroupEgress") || ($.eventName = "CreateSecurityGroup") || ($.eventName = "DeleteSecurityGroup") }',
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

        current_audit_info = self.set_mocked_audit_info()

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
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes.logs_client",
            new=Logs(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_client",
            new=CloudWatch(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes import (
                cloudwatch_log_metric_filter_security_group_changes,
            )

            check = cloudwatch_log_metric_filter_security_group_changes()
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
    def test_cloudwatch_trail_with_log_group_with_metric_and_alarm_with_newlines(self):
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
            filterPattern='{($.eventName = "AuthorizeSecurityGroupIngress") ||\n ($.eventName = "AuthorizeSecurityGroupEgress") ||\n ($.eventName = "RevokeSecurityGroupIngress") ||\n ($.eventName = "RevokeSecurityGroupEgress") ||\n ($.eventName = "CreateSecurityGroup") ||\n ($.eventName = "DeleteSecurityGroup") }',
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

        current_audit_info = self.set_mocked_audit_info()

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
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes.logs_client",
            new=Logs(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_client",
            new=CloudWatch(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_metric_filter_security_group_changes.cloudwatch_log_metric_filter_security_group_changes import (
                cloudwatch_log_metric_filter_security_group_changes,
            )

            check = cloudwatch_log_metric_filter_security_group_changes()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "CloudWatch log group /log-group/test found with metric filter test-filter and alarms set."
            )
            assert result[0].resource_id == "/log-group/test"
