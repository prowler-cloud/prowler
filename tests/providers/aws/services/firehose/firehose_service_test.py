from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.firehose.firehose_service import (
    DatabaseSourceDescription,
    DirectPutSourceDescription,
    EncryptionStatus,
    Firehose,
    KinesisStreamSourceDescription,
    MSKSourceDescription,
    Source,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)


class Test_Firehose_Service:
    # Test Firehose Service
    @mock_aws
    def test_service(self):
        # Firehose client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        firehose = Firehose(aws_provider)
        assert firehose.service == "firehose"

    # Test Firehose Client
    @mock_aws
    def test_client(self):
        # Firehose client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        firehose = Firehose(aws_provider)
        for regional_client in firehose.regional_clients.values():
            assert regional_client.__class__.__name__ == "Firehose"

    # Test Firehose Session
    @mock_aws
    def test__get_session__(self):
        # Firehose client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        firehose = Firehose(aws_provider)
        assert firehose.session.__class__.__name__ == "Session"

    # Test Firehose List Delivery Streams
    @mock_aws
    def test_list_delivery_streams(self):
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
        delivery_stream_name = arn.split("/")[-1]

        # Firehose Client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        firehose = Firehose(aws_provider)

        assert len(firehose.delivery_streams) == 1
        assert firehose.delivery_streams[arn].arn == arn
        assert firehose.delivery_streams[arn].name == delivery_stream_name
        assert firehose.delivery_streams[arn].region == AWS_REGION_EU_WEST_1
        assert firehose.delivery_streams[arn].tags == [{"Key": "key", "Value": "value"}]

    @mock_aws
    def test_list_tags_for_delivery_stream(self):
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
        delivery_stream_name = arn.split("/")[-1]

        # Firehose Client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        firehose = Firehose(aws_provider)

        assert len(firehose.delivery_streams) == 1
        assert firehose.delivery_streams[arn].arn == arn
        assert firehose.delivery_streams[arn].name == delivery_stream_name
        assert firehose.delivery_streams[arn].region == AWS_REGION_EU_WEST_1
        assert firehose.delivery_streams[arn].tags == [{"Key": "key", "Value": "value"}]

    @mock_aws
    def test_describe_delivery_stream(self):
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
        delivery_stream_name = arn.split("/")[-1]

        firehose_client.start_delivery_stream_encryption(
            DeliveryStreamName=delivery_stream_name,
            DeliveryStreamEncryptionConfigurationInput={
                "KeyARN": f"arn:aws:kms:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:key/test-kms-key-id",
                "KeyType": "CUSTOMER_MANAGED_CMK",
            },
        )

        # Firehose Client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        firehose = Firehose(aws_provider)

        assert len(firehose.delivery_streams) == 1
        assert firehose.delivery_streams[arn].arn == arn
        assert firehose.delivery_streams[arn].name == delivery_stream_name
        assert firehose.delivery_streams[arn].region == AWS_REGION_EU_WEST_1
        assert firehose.delivery_streams[arn].tags == [{"Key": "key", "Value": "value"}]
        assert firehose.delivery_streams[arn].kms_encryption == EncryptionStatus.ENABLED
        assert (
            firehose.delivery_streams[arn].kms_key_arn
            == f"arn:aws:kms:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:key/test-kms-key-id"
        )

    @mock_aws
    def test_describe_delivery_stream_source_direct_put(self):
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

        # Firehose Client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        firehose = Firehose(aws_provider)

        assert len(firehose.delivery_streams) == 1
        assert firehose.delivery_streams[arn].delivery_stream_type == "DirectPut"

        # Test Source structure
        assert isinstance(firehose.delivery_streams[arn].source, Source)
        assert isinstance(
            firehose.delivery_streams[arn].source.direct_put, DirectPutSourceDescription
        )
        assert isinstance(
            firehose.delivery_streams[arn].source.kinesis_stream,
            KinesisStreamSourceDescription,
        )
        assert isinstance(
            firehose.delivery_streams[arn].source.msk, MSKSourceDescription
        )
        assert isinstance(
            firehose.delivery_streams[arn].source.database, DatabaseSourceDescription
        )

    @mock_aws
    def test_describe_delivery_stream_source_kinesis_stream(self):
        # Generate Kinesis client
        kinesis_client = client("kinesis", region_name=AWS_REGION_EU_WEST_1)
        kinesis_client.create_stream(
            StreamName="test-kinesis-stream",
            ShardCount=1,
        )
        kinesis_stream_arn = f"arn:aws:kinesis:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:stream/test-kinesis-stream"

        # Generate Firehose client
        firehose_client = client("firehose", region_name=AWS_REGION_EU_WEST_1)
        delivery_stream = firehose_client.create_delivery_stream(
            DeliveryStreamName="test-delivery-stream",
            DeliveryStreamType="KinesisStreamAsSource",
            KinesisStreamSourceConfiguration={
                "KinesisStreamARN": kinesis_stream_arn,
                "RoleARN": "arn:aws:iam::012345678901:role/firehose-role",
            },
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

        # Firehose Client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        firehose = Firehose(aws_provider)

        assert len(firehose.delivery_streams) == 1
        assert (
            firehose.delivery_streams[arn].delivery_stream_type
            == "KinesisStreamAsSource"
        )

        # Test Source structure
        assert isinstance(firehose.delivery_streams[arn].source, Source)
        assert isinstance(
            firehose.delivery_streams[arn].source.kinesis_stream,
            KinesisStreamSourceDescription,
        )
        assert (
            firehose.delivery_streams[arn].source.kinesis_stream.kinesis_stream_arn
            == kinesis_stream_arn
        )
