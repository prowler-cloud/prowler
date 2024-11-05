from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.firehose.firehose_service import Firehose
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider


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
        assert firehose.delivery_streams[arn].kms_encryption == "ENABLED"
        assert (
            firehose.delivery_streams[arn].kms_key_arn
            == delivery_stream["DeliveryStreamDescription"]["Destinations"][0][
                "ExtendedS3DestinationDescription"
            ]["EncryptionConfiguration"]["KMSEncryptionConfig"]["AWSKMSKeyARN"]
        )
