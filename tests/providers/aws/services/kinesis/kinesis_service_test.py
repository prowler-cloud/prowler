from unittest.mock import patch

import botocore
from moto import mock_aws

from prowler.providers.aws.services.kinesis.kinesis_service import Kinesis, StreamStatus
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListStreams":
        return {
            "StreamNames": ["test-stream"],
            "StreamSummaries": [
                {
                    "StreamName": "test-stream",
                    "StreamARN": "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream",
                    "StreamStatus": "ACTIVE",
                }
            ],
        }
    return make_api_call(self, operation_name, kwarg)


# Patch every AWS call using Boto3
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_Kinesis_Service:
    # Test Kinesis Client
    @mock_aws
    def test_get_client(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        kinesis = Kinesis(aws_provider)
        assert (
            kinesis.regional_clients[AWS_REGION_US_EAST_1].__class__.__name__
            == "Kinesis"
        )

    # Test Kinesis Session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        kinesis = Kinesis(aws_provider)
        assert kinesis.session.__class__.__name__ == "Session"

    # Test Kinesis Service
    @mock_aws
    def test__get_service__(self):
        kinesis = Kinesis(set_mocked_aws_provider())
        assert kinesis.service == "kinesis"

    @mock_aws
    def test_list_streamscomplete(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        kinesis = Kinesis(aws_provider)

        arn = "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream"
        assert len(kinesis.streams) == 1
        assert kinesis.streams[arn].name == "test-stream"
        assert kinesis.streams[arn].status == StreamStatus.ACTIVE
        assert kinesis.streams[arn].tags == []
        assert kinesis.streams[arn].region == AWS_REGION_US_EAST_1
        assert kinesis.streams[arn].arn == arn
