from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_kinesis_encrypted_at_rest:
    @mock_aws
    def test_no_streams(self):
        from prowler.providers.aws.services.kinesis.kinesis_service import Kinesis

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kinesis.kinesis_stream_data_retention_period.kinesis_stream_data_retention_period.kinesis_client",
            new=Kinesis(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.kinesis.kinesis_stream_data_retention_period.kinesis_stream_data_retention_period import (
                kinesis_stream_data_retention_period,
            )

            check = kinesis_stream_data_retention_period()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_adequate_retention_period(self):
        kinesis_client = client("kinesis", region_name=AWS_REGION_US_EAST_1)
        stream_name = "stream_test_us"
        kinesis_client.create_stream(
            StreamName=stream_name,
            ShardCount=1,
            StreamModeDetails={"StreamMode": "PROVISIONED"},
        )
        retention_period = 400
        kinesis_client.increase_stream_retention_period(
            StreamName=stream_name,
            RetentionPeriodHours=retention_period,
            StreamARN=f"arn:aws:kinesis:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:stream/{stream_name}",
        )

        kinesis_client.audit_config = mock.MagicMock()
        kinesis_client.audit_config = {"min_kinesis_stream_retention_hours": 350}

        from prowler.providers.aws.services.kinesis.kinesis_service import Kinesis

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kinesis.kinesis_stream_data_retention_period.kinesis_stream_data_retention_period.kinesis_client",
            new=Kinesis(aws_provider),
        ):
            with mock.patch(
                "prowler.providers.aws.services.kinesis.kinesis_stream_data_retention_period.kinesis_stream_data_retention_period.kinesis_client.audit_config",
                new=kinesis_client.audit_config,
            ):
                # Test Check
                from prowler.providers.aws.services.kinesis.kinesis_stream_data_retention_period.kinesis_stream_data_retention_period import (
                    kinesis_stream_data_retention_period,
                )

                check = kinesis_stream_data_retention_period()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Kinesis Stream {stream_name} does have an adequate data retention period ({retention_period}hrs)."
                )
                assert result[0].resource_id == stream_name
                assert (
                    result[0].resource_arn
                    == f"arn:aws:kinesis:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:stream/{stream_name}"
                )
                assert result[0].resource_tags == []
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_unadequate_retention_period(self):
        kinesis_client = client("kinesis", region_name=AWS_REGION_US_EAST_1)
        stream_name = "stream_test_us"
        kinesis_client.create_stream(
            StreamName=stream_name,
            ShardCount=1,
            StreamModeDetails={"StreamMode": "PROVISIONED"},
        )
        retention_period = 200
        kinesis_client.increase_stream_retention_period(
            StreamName=stream_name,
            RetentionPeriodHours=retention_period,
            StreamARN=f"arn:aws:kinesis:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:stream/{stream_name}",
        )

        kinesis_client.audit_config = mock.MagicMock()
        kinesis_client.audit_config = {"min_kinesis_stream_retention_hours": 250}

        from prowler.providers.aws.services.kinesis.kinesis_service import Kinesis

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kinesis.kinesis_stream_data_retention_period.kinesis_stream_data_retention_period.kinesis_client",
            new=Kinesis(aws_provider),
        ):
            with mock.patch(
                "prowler.providers.aws.services.kinesis.kinesis_stream_data_retention_period.kinesis_stream_data_retention_period.kinesis_client.audit_config",
                new=kinesis_client.audit_config,
            ):
                # Test Check
                from prowler.providers.aws.services.kinesis.kinesis_stream_data_retention_period.kinesis_stream_data_retention_period import (
                    kinesis_stream_data_retention_period,
                )

                check = kinesis_stream_data_retention_period()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"Kinesis Stream {stream_name} does not have an adequate data retention period ({retention_period}hrs)."
                )
                assert result[0].resource_id == stream_name
                assert (
                    result[0].resource_arn
                    == f"arn:aws:kinesis:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:stream/{stream_name}"
                )
                assert result[0].resource_tags == []
                assert result[0].region == AWS_REGION_US_EAST_1
