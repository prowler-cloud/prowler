from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_kinesis_encrypted_at_rest:
    @mock_aws
    def test_no_streams(self):
        from prowler.providers.aws.services.kinesis.kinesis_service import Kinesis

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kinesis.kinesis_stream_encrypted_at_rest.kinesis_stream_encrypted_at_rest.kinesis_client",
            new=Kinesis(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.kinesis.kinesis_stream_encrypted_at_rest.kinesis_stream_encrypted_at_rest import (
                kinesis_stream_encrypted_at_rest,
            )

            check = kinesis_stream_encrypted_at_rest()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_encrypted_stream(self):
        kinesis_client = client("kinesis", region_name=AWS_REGION_US_EAST_1)
        stream_name = "stream_test_us"
        kinesis_client.create_stream(
            StreamName=stream_name,
            ShardCount=1,
            StreamModeDetails={"StreamMode": "PROVISIONED"},
        )

        kinesis_client.start_stream_encryption(
            StreamName=stream_name,
            EncryptionType="KMS",
            KeyId="arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
        )

        from prowler.providers.aws.services.kinesis.kinesis_service import Kinesis

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kinesis.kinesis_stream_encrypted_at_rest.kinesis_stream_encrypted_at_rest.kinesis_client",
            new=Kinesis(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.kinesis.kinesis_stream_encrypted_at_rest.kinesis_stream_encrypted_at_rest import (
                kinesis_stream_encrypted_at_rest,
            )

            check = kinesis_stream_encrypted_at_rest()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Kinesis Stream {stream_name} is encrypted at rest."
            )
            assert result[0].resource_id == stream_name
            assert (
                result[0].resource_arn
                == f"arn:aws:kinesis:{AWS_REGION_US_EAST_1}:123456789012:stream/{stream_name}"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_non_encrypted_stream(self):
        kinesis_client = client("kinesis", region_name=AWS_REGION_US_EAST_1)
        stream_name = "stream_test_us"
        kinesis_client.create_stream(
            StreamName=stream_name,
            ShardCount=1,
            StreamModeDetails={"StreamMode": "PROVISIONED"},
        )

        from prowler.providers.aws.services.kinesis.kinesis_service import Kinesis

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kinesis.kinesis_stream_encrypted_at_rest.kinesis_stream_encrypted_at_rest.kinesis_client",
            new=Kinesis(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.kinesis.kinesis_stream_encrypted_at_rest.kinesis_stream_encrypted_at_rest import (
                kinesis_stream_encrypted_at_rest,
            )

            check = kinesis_stream_encrypted_at_rest()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Kinesis Stream {stream_name} is not encrypted at rest."
            )
            assert result[0].resource_id == stream_name
            assert (
                result[0].resource_arn
                == f"arn:aws:kinesis:{AWS_REGION_US_EAST_1}:123456789012:stream/{stream_name}"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1
