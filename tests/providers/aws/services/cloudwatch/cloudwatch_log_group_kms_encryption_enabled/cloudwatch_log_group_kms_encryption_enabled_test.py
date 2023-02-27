from unittest import mock

from boto3 import client
from moto import mock_logs

AWS_REGION = "us-east-1"


class Test_cloudwatch_log_group_kms_encryption_enabled:
    def test_cloudwatch_no_log_groups(self):
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs
        from prowler.providers.common.models import Audit_Metadata

        current_audit_info.audited_partition = "aws"
        current_audit_info.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call __describe_log_groups__
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_kms_encryption_enabled.cloudwatch_log_group_kms_encryption_enabled.logs_client",
            new=Logs(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_kms_encryption_enabled.cloudwatch_log_group_kms_encryption_enabled import (
                cloudwatch_log_group_kms_encryption_enabled,
            )

            check = cloudwatch_log_group_kms_encryption_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_logs
    def test_cloudwatch_log_group_without_kms_key(self):
        # Generate Logs Client
        logs_client = client("logs", region_name=AWS_REGION)
        # Request Logs group
        logs_client.create_log_group(
            logGroupName="test",
        )
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs
        from prowler.providers.common.models import Audit_Metadata

        current_audit_info.audited_partition = "aws"
        current_audit_info.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call __describe_log_groups__
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_kms_encryption_enabled.cloudwatch_log_group_kms_encryption_enabled.logs_client",
            new=Logs(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_kms_encryption_enabled.cloudwatch_log_group_kms_encryption_enabled import (
                cloudwatch_log_group_kms_encryption_enabled,
            )

            check = cloudwatch_log_group_kms_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Log Group test does not have AWS KMS keys associated."
            )
            assert result[0].resource_id == "test"

    @mock_logs
    def test_cloudwatch_log_group_with_kms_key(self):
        # Generate Logs Client
        logs_client = client("logs", region_name=AWS_REGION)
        # Request Logs group
        logs_client.create_log_group(logGroupName="test", kmsKeyId="test_kms_id")
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs
        from prowler.providers.common.models import Audit_Metadata

        current_audit_info.audited_partition = "aws"
        current_audit_info.audit_metadata = Audit_Metadata(
            services_scanned=0,
            # We need to set this check to call __describe_log_groups__
            expected_checks=["cloudwatch_log_group_no_secrets_in_logs"],
            completed_checks=0,
            audit_progress=0,
        )

        with mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_kms_encryption_enabled.cloudwatch_log_group_kms_encryption_enabled.logs_client",
            new=Logs(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_kms_encryption_enabled.cloudwatch_log_group_kms_encryption_enabled import (
                cloudwatch_log_group_kms_encryption_enabled,
            )

            check = cloudwatch_log_group_kms_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Log Group test does have AWS KMS key test_kms_id associated."
            )
            assert result[0].resource_id == "test"
