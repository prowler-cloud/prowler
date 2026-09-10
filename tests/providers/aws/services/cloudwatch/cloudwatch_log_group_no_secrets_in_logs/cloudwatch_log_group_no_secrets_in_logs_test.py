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

    @mock_aws
    def test_two_multiline_events_same_timestamp_do_not_collide(self):
        # Regression: a CloudWatch stream can hold several events sharing one
        # millisecond timestamp. The multiline rescan must be keyed per event
        # (not only per timestamp), otherwise the later event's payload
        # overwrites the earlier one and secret evidence is lost.
        log_group_arn = (
            f"arn:aws:logs:{AWS_REGION_US_EAST_1}:123456789012:log-group:test:*"
        )
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        logs_client.create_log_group(logGroupName="test", tags={"test": "test"})
        logs_client.create_log_stream(logGroupName="test", logStreamName="test stream")
        # Two distinct multiline (valid JSON) events at the same timestamp.
        logs_client.put_log_events(
            logGroupName="test",
            logStreamName="test stream",
            logEvents=[
                {
                    "timestamp": timestamp,
                    "message": '{"api_key": "AKIAIOSFODNN7EXAMPLE", "note": "a"}',
                },
                {
                    "timestamp": timestamp,
                    "message": '{"secret": "AKIAI44QH8DHBEXAMPLE", "note": "b"}',
                },
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
                    # Phase 1: both events flagged (one secret on each line).
                    {
                        (log_group_arn, "test stream"): [
                            {
                                "type": "AWS Access Key",
                                "line_number": 1,
                                "filename": "data",
                                "hashed_secret": "a",
                                "is_verified": False,
                            },
                            {
                                "type": "AWS Access Key",
                                "line_number": 2,
                                "filename": "data",
                                "hashed_secret": "b",
                                "is_verified": False,
                            },
                        ]
                    },
                    # Phase 3: each event is rescanned under its own key. If the
                    # keys collided, only one of these would survive.
                    {
                        (
                            log_group_arn,
                            "test stream",
                            dttimestamp,
                            0,
                        ): [
                            {
                                "type": "AWS Access Key",
                                "line_number": 2,
                                "filename": "data",
                                "hashed_secret": "a",
                                "is_verified": False,
                            }
                        ],
                        (
                            log_group_arn,
                            "test stream",
                            dttimestamp,
                            1,
                        ): [
                            {
                                "type": "AWS Access Key",
                                "line_number": 2,
                                "filename": "data",
                                "hashed_secret": "b",
                                "is_verified": False,
                            }
                        ],
                    },
                ],
            ),
        ):
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_no_secrets_in_logs.cloudwatch_log_group_no_secrets_in_logs import (
                cloudwatch_log_group_no_secrets_in_logs,
            )

            check = cloudwatch_log_group_no_secrets_in_logs()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            # Both events' secrets must be reported, not just the last one.
            assert (
                result[0].status_extended
                == f"Potential secrets found in log group test in log stream test stream at {dttimestamp} - AWS Access Key on line 2."
            )

    @mock_aws
    def test_same_group_and_stream_names_in_two_regions_do_not_collide(self):
        # Regression: log group and stream names are not unique across regions,
        # so the per-stream key must be region-aware (ARN-based). Otherwise the
        # secret found in one region would be reused for the same-named group in
        # another region, producing a false FAIL.
        group_name = "shared-name"
        stream_name = "shared stream"

        us_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        us_client.create_log_group(logGroupName=group_name)
        us_client.create_log_stream(logGroupName=group_name, logStreamName=stream_name)
        us_client.put_log_events(
            logGroupName=group_name,
            logStreamName=stream_name,
            logEvents=[
                {
                    "timestamp": timestamp,
                    "message": 'password = "Tr0ub4dor3xKq9vLmZ"',
                }
            ],
        )

        eu_client = client("logs", region_name=AWS_REGION_EU_WEST_1)
        eu_client.create_log_group(logGroupName=group_name)
        eu_client.create_log_stream(logGroupName=group_name, logStreamName=stream_name)
        eu_client.put_log_events(
            logGroupName=group_name,
            logStreamName=stream_name,
            logEvents=[{"timestamp": timestamp, "message": "just a normal log line"}],
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
        ):
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_no_secrets_in_logs.cloudwatch_log_group_no_secrets_in_logs import (
                cloudwatch_log_group_no_secrets_in_logs,
            )

            check = cloudwatch_log_group_no_secrets_in_logs()
            result = check.execute()

            assert len(result) == 2
            by_region = {report.region: report for report in result}
            # Only the region with the real secret must FAIL.
            assert by_region[AWS_REGION_US_EAST_1].status == "FAIL"
            assert by_region[AWS_REGION_EU_WEST_1].status == "PASS"
