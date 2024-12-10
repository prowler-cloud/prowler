from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)


class Test_firehose_stream_encrypted_at_rest:
    @mock_aws
    def test_no_streams(self):
        from prowler.providers.aws.services.firehose.firehose_service import Firehose

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.firehose.firehose_stream_encrypted_at_rest.firehose_stream_encrypted_at_rest.firehose_client",
                new=Firehose(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.firehose.firehose_stream_encrypted_at_rest.firehose_stream_encrypted_at_rest import (
                firehose_stream_encrypted_at_rest,
            )

            check = firehose_stream_encrypted_at_rest()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_stream_kms_encryption_enabled(self):
        # Generate S3 client
        s3_client = client("s3", region_name=AWS_REGION_EU_WEST_1)
        s3_client.create_bucket(
            Bucket="test-bucket",
            CreateBucketConfiguration={"LocationConstraint": AWS_REGION_EU_WEST_1},
        )

        # Generate Firehose client
        firehose_client = client("firehose", region_name=AWS_REGION_EU_WEST_1)
        delivery_stream = firehose_client.create_delivery_stream(
            DeliveryStreamName="test-delivery-stream",
            DeliveryStreamType="DirectPut",
            S3DestinationConfiguration={
                "RoleARN": "arn:aws:iam::012345678901:role/firehose-role",
                "BucketARN": "arn:aws:s3:::test-bucket",
                "Prefix": "",
                "BufferingHints": {"IntervalInSeconds": 300, "SizeInMBs": 5},
                "CompressionFormat": "UNCOMPRESSED",
            },
            Tags=[{"Key": "key", "Value": "value"}],
        )
        arn = delivery_stream["DeliveryStreamARN"]
        stream_name = arn.split("/")[-1]

        firehose_client.start_delivery_stream_encryption(
            DeliveryStreamName=stream_name,
            DeliveryStreamEncryptionConfigurationInput={
                "KeyARN": f"arn:aws:kms:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:key/test-kms-key-id",
                "KeyType": "CUSTOMER_MANAGED_CMK",
            },
        )

        from prowler.providers.aws.services.firehose.firehose_service import Firehose

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.firehose.firehose_stream_encrypted_at_rest.firehose_stream_encrypted_at_rest.firehose_client",
                new=Firehose(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.firehose.firehose_stream_encrypted_at_rest.firehose_stream_encrypted_at_rest import (
                    firehose_stream_encrypted_at_rest,
                )

                check = firehose_stream_encrypted_at_rest()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Firehose Stream {stream_name} does have at rest encryption enabled."
                )

    @mock_aws
    def test_stream_kms_encryption_enabled_aws_managed_key(self):
        # Generate S3 client
        s3_client = client("s3", region_name=AWS_REGION_EU_WEST_1)
        s3_client.create_bucket(
            Bucket="test-bucket",
            CreateBucketConfiguration={"LocationConstraint": AWS_REGION_EU_WEST_1},
        )

        # Generate Firehose client
        firehose_client = client("firehose", region_name=AWS_REGION_EU_WEST_1)
        delivery_stream = firehose_client.create_delivery_stream(
            DeliveryStreamName="test-delivery-stream",
            DeliveryStreamType="DirectPut",
            S3DestinationConfiguration={
                "RoleARN": "arn:aws:iam::012345678901:role/firehose-role",
                "BucketARN": "arn:aws:s3:::test-bucket",
                "Prefix": "",
                "BufferingHints": {"IntervalInSeconds": 300, "SizeInMBs": 5},
                "CompressionFormat": "UNCOMPRESSED",
            },
            Tags=[{"Key": "key", "Value": "value"}],
        )
        arn = delivery_stream["DeliveryStreamARN"]
        stream_name = arn.split("/")[-1]

        firehose_client.start_delivery_stream_encryption(
            DeliveryStreamName=stream_name,
            DeliveryStreamEncryptionConfigurationInput={
                "KeyType": "AWS_OWNED_CMK",
            },
        )

        from prowler.providers.aws.services.firehose.firehose_service import Firehose

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.firehose.firehose_stream_encrypted_at_rest.firehose_stream_encrypted_at_rest.firehose_client",
                new=Firehose(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.firehose.firehose_stream_encrypted_at_rest.firehose_stream_encrypted_at_rest import (
                    firehose_stream_encrypted_at_rest,
                )

                check = firehose_stream_encrypted_at_rest()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Firehose Stream {stream_name} does have at rest encryption enabled."
                )

    @mock_aws
    def test_stream_kms_encryption_not_enabled(self):
        # Generate Firehose client
        firehose_client = client("firehose", region_name=AWS_REGION_EU_WEST_1)
        delivery_stream = firehose_client.create_delivery_stream(
            DeliveryStreamName="test-delivery-stream",
            DeliveryStreamType="DirectPut",
            S3DestinationConfiguration={
                "RoleARN": "arn:aws:iam::012345678901:role/firehose-role",
                "BucketARN": "arn:aws:s3:::test-bucket",
                "Prefix": "",
                "BufferingHints": {"IntervalInSeconds": 300, "SizeInMBs": 5},
                "CompressionFormat": "UNCOMPRESSED",
            },
            Tags=[{"Key": "key", "Value": "value"}],
        )
        arn = delivery_stream["DeliveryStreamARN"]
        stream_name = arn.split("/")[-1]

        from prowler.providers.aws.services.firehose.firehose_service import Firehose

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.firehose.firehose_stream_encrypted_at_rest.firehose_stream_encrypted_at_rest.firehose_client",
                new=Firehose(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.firehose.firehose_stream_encrypted_at_rest.firehose_stream_encrypted_at_rest import (
                    firehose_stream_encrypted_at_rest,
                )

                check = firehose_stream_encrypted_at_rest()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"Firehose Stream {stream_name} does not have at rest encryption enabled."
                )

    @mock_aws
    def test_stream_kms_encryption_disabled(self):
        # Generate Firehose client
        firehose_client = client("firehose", region_name=AWS_REGION_EU_WEST_1)
        delivery_stream = firehose_client.create_delivery_stream(
            DeliveryStreamName="test-delivery-stream",
            DeliveryStreamType="DirectPut",
            S3DestinationConfiguration={
                "RoleARN": "arn:aws:iam::012345678901:role/firehose-role",
                "BucketARN": "arn:aws:s3:::test-bucket",
                "Prefix": "",
                "BufferingHints": {"IntervalInSeconds": 300, "SizeInMBs": 5},
                "CompressionFormat": "UNCOMPRESSED",
            },
            Tags=[{"Key": "key", "Value": "value"}],
        )
        arn = delivery_stream["DeliveryStreamARN"]
        stream_name = arn.split("/")[-1]

        firehose_client.start_delivery_stream_encryption(
            DeliveryStreamName=stream_name,
            DeliveryStreamEncryptionConfigurationInput={
                "KeyARN": f"arn:aws:kms:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:key/test-kms-key-id",
                "KeyType": "CUSTOMER_MANAGED_CMK",
            },
        )

        firehose_client.stop_delivery_stream_encryption(DeliveryStreamName=stream_name)

        from prowler.providers.aws.services.firehose.firehose_service import Firehose

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.firehose.firehose_stream_encrypted_at_rest.firehose_stream_encrypted_at_rest.firehose_client",
                new=Firehose(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.firehose.firehose_stream_encrypted_at_rest.firehose_stream_encrypted_at_rest import (
                    firehose_stream_encrypted_at_rest,
                )

                check = firehose_stream_encrypted_at_rest()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"Firehose Stream {stream_name} does not have at rest encryption enabled."
                )
