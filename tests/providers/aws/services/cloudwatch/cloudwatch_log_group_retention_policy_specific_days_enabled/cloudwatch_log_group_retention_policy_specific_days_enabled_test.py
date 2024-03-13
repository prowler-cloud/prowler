from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_cloudwatch_log_group_retention_policy_specific_days_enabled:
    def test_cloudwatch_no_log_groups(self):
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        aws_provider._audit_config = {"log_group_retention_days": 365}

        from prowler.providers.common.models import Audit_Metadata

        aws_provider.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call __describe_log_groups__
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_retention_policy_specific_days_enabled.cloudwatch_log_group_retention_policy_specific_days_enabled.logs_client",
            new=Logs(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_retention_policy_specific_days_enabled.cloudwatch_log_group_retention_policy_specific_days_enabled import (
                cloudwatch_log_group_retention_policy_specific_days_enabled,
            )

            check = cloudwatch_log_group_retention_policy_specific_days_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_cloudwatch_log_group_without_retention_days_never_expires(self):
        # Generate Logs Client
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        # Request Logs group
        logs_client.create_log_group(
            logGroupName="test",
        )
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        aws_provider._audit_config = {"log_group_retention_days": 365}

        from prowler.providers.common.models import Audit_Metadata

        aws_provider.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call __describe_log_groups__
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_retention_policy_specific_days_enabled.cloudwatch_log_group_retention_policy_specific_days_enabled.logs_client",
            new=Logs(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_retention_policy_specific_days_enabled.cloudwatch_log_group_retention_policy_specific_days_enabled import (
                cloudwatch_log_group_retention_policy_specific_days_enabled,
            )

            check = cloudwatch_log_group_retention_policy_specific_days_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Log Group test comply with 365 days retention period since it never expires."
            )
            assert result[0].resource_id == "test"
            assert (
                result[0].resource_arn
                == f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:test"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_cloudwatch_log_group_with_compliant_retention_days(self):
        # Generate Logs Client
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        # Request Logs group
        logs_client.create_log_group(
            logGroupName="test",
        )
        logs_client.put_retention_policy(logGroupName="test", retentionInDays=400)
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        aws_provider._audit_config = {"log_group_retention_days": 365}

        from prowler.providers.common.models import Audit_Metadata

        aws_provider.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call __describe_log_groups__
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_retention_policy_specific_days_enabled.cloudwatch_log_group_retention_policy_specific_days_enabled.logs_client",
            new=Logs(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_retention_policy_specific_days_enabled.cloudwatch_log_group_retention_policy_specific_days_enabled import (
                cloudwatch_log_group_retention_policy_specific_days_enabled,
            )

            check = cloudwatch_log_group_retention_policy_specific_days_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Log Group test comply with 365 days retention period since it has 400 days."
            )
            assert result[0].resource_id == "test"
            assert (
                result[0].resource_arn
                == f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:test"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_cloudwatch_log_group_with_no_compliant_retention_days(self):
        # Generate Logs Client
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        # Request Logs group
        logs_client.create_log_group(
            logGroupName="test",
        )
        logs_client.put_retention_policy(logGroupName="test", retentionInDays=7)
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        aws_provider._audit_config = {"log_group_retention_days": 365}

        from prowler.providers.common.models import Audit_Metadata

        aws_provider.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call __describe_log_groups__
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_retention_policy_specific_days_enabled.cloudwatch_log_group_retention_policy_specific_days_enabled.logs_client",
            new=Logs(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_retention_policy_specific_days_enabled.cloudwatch_log_group_retention_policy_specific_days_enabled import (
                cloudwatch_log_group_retention_policy_specific_days_enabled,
            )

            check = cloudwatch_log_group_retention_policy_specific_days_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Log Group test has less than 365 days retention period (7 days)."
            )
            assert result[0].resource_id == "test"
            assert (
                result[0].resource_arn
                == f"arn:aws:logs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:log-group:test"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
