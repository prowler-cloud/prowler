from datetime import datetime
from unittest import mock

from boto3 import client
from moto import mock_aws
from moto.core.utils import unix_time_millis

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

timestamp = int(unix_time_millis())
dttimestamp = (
    (datetime.fromtimestamp(timestamp / 1000))
    .astimezone()
    .isoformat(timespec="milliseconds")
)


class Test_cloudwatch_log_group_no_secrets_in_logs:
    def test_cloudwatch_no_log_groups(self):
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs

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
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_no_secrets_in_logs.cloudwatch_log_group_no_secrets_in_logs.logs_client",
                new=Logs(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_no_secrets_in_logs.cloudwatch_log_group_no_secrets_in_logs import (
                cloudwatch_log_group_no_secrets_in_logs,
            )

            check = cloudwatch_log_group_no_secrets_in_logs()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_cloudwatch_log_group_without_secrets(self):
        # Generate Logs Client
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        # Request Logs group
        logs_client.create_log_group(logGroupName="test", tags={"test": "test"})
        logs_client.create_log_stream(logGroupName="test", logStreamName="test stream")
        logs_client.put_log_events(
            logGroupName="test",
            logStreamName="test stream",
            logEvents=[
                {
                    "timestamp": timestamp,
                    "message": "non sensitive message",
                }
            ],
        )
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs

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
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_no_secrets_in_logs.cloudwatch_log_group_no_secrets_in_logs.logs_client",
                new=Logs(aws_provider),
            ),
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
            assert (
                result[0].resource_arn
                == f"arn:aws:logs:{AWS_REGION_US_EAST_1}:123456789012:log-group:test:*"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{}]

    @mock_aws
    def test_cloudwatch_log_group_with_secrets(self):
        # Generate Logs Client
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        # Request Logs group
        logs_client.create_log_group(logGroupName="test", tags={"test": "test"})
        logs_client.create_log_stream(logGroupName="test", logStreamName="test stream")
        logs_client.put_log_events(
            logGroupName="test",
            logStreamName="test stream",
            logEvents=[
                {
                    "timestamp": timestamp,
                    "message": 'password = "Tr0ub4dor3xKq9vLmZ"',
                }
            ],
        )
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs

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
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_no_secrets_in_logs.cloudwatch_log_group_no_secrets_in_logs.logs_client",
                new=Logs(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_no_secrets_in_logs.cloudwatch_log_group_no_secrets_in_logs import (
                cloudwatch_log_group_no_secrets_in_logs,
            )

            check = cloudwatch_log_group_no_secrets_in_logs()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secrets found in log group test in log stream test stream at {dttimestamp} - Generic Password on line 1."
            )
            assert result[0].resource_id == "test"
            assert (
                result[0].resource_arn
                == f"arn:aws:logs:{AWS_REGION_US_EAST_1}:123456789012:log-group:test:*"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{}]

    @mock_aws
    def test_access_denied(self):
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs

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
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_no_secrets_in_logs.cloudwatch_log_group_no_secrets_in_logs.logs_client",
                new=Logs(aws_provider),
            ) as logs_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_no_secrets_in_logs.cloudwatch_log_group_no_secrets_in_logs import (
                cloudwatch_log_group_no_secrets_in_logs,
            )

            logs_client.log_groups = None
            check = cloudwatch_log_group_no_secrets_in_logs()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_cloudwatch_multiline_event_all_secrets_ignored_is_pass(self):
        # Regression: a multiline event whose secrets are all dropped by the
        # rescan (e.g. filtered by secrets_ignore_patterns) must NOT produce a
        # FAIL with no actual secret evidence.
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        logs_client.create_log_group(logGroupName="test", tags={"test": "test"})
        logs_client.create_log_stream(logGroupName="test", logStreamName="test stream")
        logs_client.put_log_events(
            logGroupName="test",
            logStreamName="test stream",
            logEvents=[
                {
                    "timestamp": timestamp,
                    # Valid JSON so the rescan expands it to multiple lines.
                    "message": '{"api_key": "AKIAIOSFODNN7EXAMPLE", "note": "x"}',
                }
            ],
        )
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        from prowler.providers.common.models import Audit_Metadata

        aws_provider.audit_metadata = Audit_Metadata(
            services_scanned=0,
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
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_no_secrets_in_logs.cloudwatch_log_group_no_secrets_in_logs.logs_client",
                new=Logs(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_no_secrets_in_logs.cloudwatch_log_group_no_secrets_in_logs.detect_secrets_scan_batch",
                side_effect=[
                    # Phase 1: stream flagged on its single (multiline) event.
                    {
                        ("test", "test stream"): [
                            {
                                "type": "AWS Access Key",
                                "line_number": 1,
                                "filename": "data",
                                "hashed_secret": "x",
                                "is_verified": False,
                            }
                        ]
                    },
                    # Phase 3: rescan drops everything (all secrets ignored).
                    {},
                ],
            ),
        ):
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_no_secrets_in_logs.cloudwatch_log_group_no_secrets_in_logs import (
                cloudwatch_log_group_no_secrets_in_logs,
            )

            check = cloudwatch_log_group_no_secrets_in_logs()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "No secrets found in test log group."

    @mock_aws
    def test_cloudwatch_scan_failure_reports_manual(self):
        # A scanner failure on the stream scan must surface as MANUAL, not PASS.
        from prowler.lib.utils.utils import SecretsScanError

        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        logs_client.create_log_group(logGroupName="test", tags={"test": "test"})
        logs_client.create_log_stream(logGroupName="test", logStreamName="test stream")
        logs_client.put_log_events(
            logGroupName="test",
            logStreamName="test stream",
            logEvents=[{"timestamp": timestamp, "message": "some log line"}],
        )
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        from prowler.providers.common.models import Audit_Metadata

        aws_provider.audit_metadata = Audit_Metadata(
            services_scanned=0,
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
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_no_secrets_in_logs.cloudwatch_log_group_no_secrets_in_logs.logs_client",
                new=Logs(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_no_secrets_in_logs.cloudwatch_log_group_no_secrets_in_logs.detect_secrets_scan_batch",
                side_effect=SecretsScanError("Kingfisher exited with code 1"),
            ),
        ):
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_no_secrets_in_logs.cloudwatch_log_group_no_secrets_in_logs import (
                cloudwatch_log_group_no_secrets_in_logs,
            )

            check = cloudwatch_log_group_no_secrets_in_logs()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Could not scan" in result[0].status_extended
