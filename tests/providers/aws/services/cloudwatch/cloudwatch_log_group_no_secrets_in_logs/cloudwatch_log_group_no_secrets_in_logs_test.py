from re import search
from unittest import mock

from boto3 import client
from moto import mock_logs
from moto.core.utils import unix_time_millis

AWS_REGION = "us-east-1"


class Test_cloudwatch_log_group_no_secrets_in_logs:
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
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_no_secrets_in_logs.cloudwatch_log_group_no_secrets_in_logs.logs_client",
            new=Logs(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_no_secrets_in_logs.cloudwatch_log_group_no_secrets_in_logs import (
                cloudwatch_log_group_no_secrets_in_logs,
            )

            check = cloudwatch_log_group_no_secrets_in_logs()
            result = check.execute()

            assert len(result) == 0

    @mock_logs
    def test_cloudwatch_log_group_without_secrets(self):
        # Generate Logs Client
        logs_client = client("logs", region_name=AWS_REGION)
        # Request Logs group
        logs_client.create_log_group(logGroupName="test")
        logs_client.create_log_stream(logGroupName="test", logStreamName="test stream")
        logs_client.put_log_events(
            logGroupName="test",
            logStreamName="test stream",
            logEvents=[{"timestamp": 0, "message": "line"}],
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
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_no_secrets_in_logs.cloudwatch_log_group_no_secrets_in_logs.logs_client",
            new=Logs(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_no_secrets_in_logs.cloudwatch_log_group_no_secrets_in_logs import (
                cloudwatch_log_group_no_secrets_in_logs,
            )

            check = cloudwatch_log_group_no_secrets_in_logs()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "No secrets found in test log group."
            assert result[0].resource_id == "test"

    @mock_logs
    def test_cloudwatch_log_group_with_secrets(self):
        # Generate Logs Client
        logs_client = client("logs", region_name=AWS_REGION)
        # Request Logs group
        logs_client.create_log_group(logGroupName="test")
        logs_client.create_log_stream(logGroupName="test", logStreamName="test stream")
        logs_client.put_log_events(
            logGroupName="test",
            logStreamName="test stream",
            logEvents=[
                {
                    "timestamp": int(unix_time_millis()),
                    "message": "password = password123",
                }
            ],
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
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_no_secrets_in_logs.cloudwatch_log_group_no_secrets_in_logs.logs_client",
            new=Logs(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_no_secrets_in_logs.cloudwatch_log_group_no_secrets_in_logs import (
                cloudwatch_log_group_no_secrets_in_logs,
            )

            check = cloudwatch_log_group_no_secrets_in_logs()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "Potential secrets found in log group", result[0].status_extended
            )
            assert result[0].resource_id == "test"
