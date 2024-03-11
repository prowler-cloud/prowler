from json import dumps
from unittest.mock import patch
from uuid import uuid4

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.sqs.sqs_service import SQS
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

test_queue = "test-queue"
test_key = str(uuid4())
test_queue_arn = f"arn:aws:sqs:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:{test_queue}"
test_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "sqs:SendMessage",
            "Resource": test_queue_arn,
        }
    ],
}

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "GetQueueAttributes":
        return {
            "Attributes": {"Policy": dumps(test_policy), "KmsMasterKeyId": test_key}
        }
    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_SQS_Service:
    # Test SQS Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sqs = SQS(aws_provider)
        assert sqs.service == "sqs"

    # Test SQS client
    def test_client(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sqs = SQS(aws_provider)
        for reg_client in sqs.regional_clients.values():
            assert reg_client.__class__.__name__ == "SQS"

    # Test SQS session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sqs = SQS(aws_provider)
        assert sqs.session.__class__.__name__ == "Session"

    @mock_aws
    # Test SQS list queues
    def test__list_queues__(self):
        sqs_client = client("sqs", region_name=AWS_REGION_EU_WEST_1)
        queue = sqs_client.create_queue(QueueName=test_queue, tags={"test": "test"})
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sqs = SQS(aws_provider)
        assert len(sqs.queues) == 1
        assert sqs.queues[0].id == queue["QueueUrl"]
        assert sqs.queues[0].name == test_queue
        assert sqs.queues[0].name == sqs.queues[0].arn.split(":")[-1]
        assert sqs.queues[0].name == sqs.queues[0].id.split("/")[-1]
        assert sqs.queues[0].arn == test_queue_arn
        assert sqs.queues[0].region == AWS_REGION_EU_WEST_1
        assert sqs.queues[0].tags == [{"test": "test"}]

    # moto does not properly mock this and is hardcoded to return 1000 queues
    # so this test currently always fails
    # @mock_aws
    # # Test SQS list queues for over 1000 queues
    # def test__list_queues__pagination_over_a_thousand(self):
    #     sqs_client = client("sqs", region_name=AWS_REGION_EU_WEST_1)
    #     for i in range(0,1050):
    #         sqs_client.create_queue(QueueName=f"{test_queue}-{i}", tags={"test": "test"})
    #     aws_provider =set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
    #     sqs = SQS(aws_provider)
    #     assert len(sqs.queues) > 1000

    @mock_aws
    # Test SQS list queues
    def test__get_queue_attributes__(self):
        sqs_client = client("sqs", region_name=AWS_REGION_EU_WEST_1)
        queue = sqs_client.create_queue(
            QueueName=test_queue,
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sqs = SQS(aws_provider)
        assert len(sqs.queues) == 1
        assert sqs.queues[0].id == queue["QueueUrl"]
        assert sqs.queues[0].region == AWS_REGION_EU_WEST_1
        assert sqs.queues[0].policy
        assert sqs.queues[0].kms_key_id == test_key
