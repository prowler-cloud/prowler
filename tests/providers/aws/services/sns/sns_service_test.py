from json import dumps
from unittest.mock import patch
from uuid import uuid4

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.sns.sns_service import SNS
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

topic_name = "test-topic"
test_policy = {
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": f"{AWS_ACCOUNT_NUMBER}"},
            "Action": ["sns:Publish"],
            "Resource": f"arn:aws:sns:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:{topic_name}",
        }
    ]
}
kms_key_id = str(uuid4())

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "GetTopicAttributes":
        return {
            "Attributes": {"Policy": dumps(test_policy), "KmsMasterKeyId": kms_key_id}
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
class Test_SNS_Service:
    # Test SNS Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sns = SNS(aws_provider)
        assert sns.service == "sns"

    # Test SNS client
    def test_client(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sns = SNS(aws_provider)
        for reg_client in sns.regional_clients.values():
            assert reg_client.__class__.__name__ == "SNS"

    # Test SNS session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sns = SNS(aws_provider)
        assert sns.session.__class__.__name__ == "Session"

    @mock_aws
    # Test SNS session
    def test_list_topics(self):
        sns_client = client("sns", region_name=AWS_REGION_EU_WEST_1)
        sns_client.create_topic(
            Name=topic_name,
            Tags=[
                {"Key": "test", "Value": "test"},
            ],
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sns = SNS(aws_provider)

        assert len(sns.topics) == 1
        assert sns.topics[0].name == topic_name
        assert (
            sns.topics[0].arn
            == f"arn:aws:sns:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:{topic_name}"
        )
        assert sns.topics[0].region == AWS_REGION_EU_WEST_1
        assert sns.topics[0].tags == [
            {"Key": "test", "Value": "test"},
        ]

    @mock_aws
    # Test SNS session
    def test_get_topic_attributes(self):
        sns_client = client("sns", region_name=AWS_REGION_EU_WEST_1)
        sns_client.create_topic(Name=topic_name)

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sns = SNS(aws_provider)

        assert len(sns.topics) == 1
        assert (
            sns.topics[0].arn
            == f"arn:aws:sns:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:{topic_name}"
        )
        assert sns.topics[0].region == AWS_REGION_EU_WEST_1
        assert sns.topics[0].policy
        assert sns.topics[0].kms_master_key_id == kms_key_id

    @mock_aws
    def test_list_subscriptions_by_topic(self):
        sns_client = client("sns", region_name=AWS_REGION_EU_WEST_1)
        topic_response = sns_client.create_topic(Name=topic_name)
        topic_arn = topic_response["TopicArn"]

        # Create subscriptions for the topic
        sns_client.subscribe(
            TopicArn=topic_arn, Protocol="http", Endpoint="http://www.endpoint.com"
        )
        sns_client.subscribe(
            TopicArn=topic_arn, Protocol="https", Endpoint="https://www.endpoint.com"
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sns = SNS(aws_provider)

        assert len(sns.topics) == 1
        assert sns.topics[0].arn == topic_arn
        assert len(sns.topics[0].subscriptions) == 2
        assert sns.topics[0].subscriptions[0].protocol == "http"
        assert sns.topics[0].subscriptions[1].protocol == "https"
        assert sns.topics[0].subscriptions[0].endpoint == "http://www.endpoint.com"
        assert sns.topics[0].subscriptions[1].endpoint == "https://www.endpoint.com"
