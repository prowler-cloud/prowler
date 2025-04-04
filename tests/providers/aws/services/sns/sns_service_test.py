from json import dumps
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import botocore
from boto3 import client
from botocore.exceptions import ClientError
from moto import mock_aws

from prowler.providers.aws.services.sns.sns_service import SNS, Topic
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
    def test_service(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sns = SNS(aws_provider)
        assert sns.service == "sns"

    def test_client(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sns = SNS(aws_provider)
        for reg_client in sns.regional_clients.values():
            assert reg_client.__class__.__name__ == "SNS"

    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sns = SNS(aws_provider)
        assert sns.session.__class__.__name__ == "Session"

    @mock_aws
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

    def test_list_tags_for_resource_resource_not_found(self):
        """
        Test that SNS._list_tags_for_resource gracefully handles a
        ClientError with error code "ResourceNotFoundException" and does not assign tags.
        """

        class FakeClient:
            region = "us-east-1"

            def list_tags_for_resource(self, _):
                error_response = {
                    "Error": {
                        "Code": "ResourceNotFoundException",
                        "Message": "Not Found",
                    }
                }
                raise ClientError(error_response, "ListTagsForResource")

        aws_provider = set_mocked_aws_provider(["us-east-1"])
        sns = SNS(aws_provider)
        sns.regional_clients["us-east-1"] = FakeClient()
        dummy_topic = Topic(
            name="dummy",
            arn="arn:aws:sns:us-east-1:123456789012:dummy",
            region="us-east-1",
            tags=[],
        )
        sns._list_tags_for_resource(dummy_topic)
        assert dummy_topic.tags == []

    def test_list_tags_for_resource_other_error(self):
        """
        Test that SNS._list_tags_for_resource gracefully handles a ClientError with an error
        code other than "ResourceNotFoundException" (e.g., "SomeOtherError") and does not assign
        any tags to the resource.
        """

        class FakeClientOther:
            region = "us-west-1"

            def list_tags_for_resource(self, _):
                error_response = {
                    "Error": {"Code": "SomeOtherError", "Message": "Some Other Error"}
                }
                raise ClientError(error_response, "ListTagsForResource")

        aws_provider = set_mocked_aws_provider(["us-west-1"])
        sns = SNS(aws_provider)
        sns.regional_clients["us-west-1"] = FakeClientOther()
        dummy_topic = Topic(
            name="dummy",
            arn="arn:aws:sns:us-west-1:123456789012:dummy",
            region="us-west-1",
            tags=[],
        )
        sns._list_tags_for_resource(dummy_topic)
        assert dummy_topic.tags == []

    @patch("prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients")
    def test_list_topics_exception(self, mock_generate_regional_clients):
        """
        Test that SNS._list_topics gracefully handles an exception thrown during topic listing.
        In this test a fake regional client is provided that always raises an exception when
        calling get_paginator("list_topics"). As a result, SNS.topics should remain empty.
        """

        # Define a fake generate_regional_clients that returns a fake regional client raising an exception.
        def fake_generate_regional_clients(provider, service):
            class ExceptionFakePaginator:
                def paginate(self):
                    raise Exception("Test exception in list_topics")

            class FakeClient:
                region = AWS_REGION_EU_WEST_1

                def get_paginator(self, operation_name):
                    return ExceptionFakePaginator()

            return {AWS_REGION_EU_WEST_1: FakeClient()}

        mock_generate_regional_clients.side_effect = (
            lambda provider, service: fake_generate_regional_clients(provider, service)
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        sns = SNS(aws_provider)
        # Since get_paginator always raises an exception, topics should remain empty
        assert sns.topics == []

    def test_get_topic_attributes_exception(self, caplog):
        """
        Test that SNS._get_topic_attributes gracefully handles an exception thrown during
        get_topic_attributes and does not update the topic's attributes.
        """
        # Create an AWS provider with a dummy region
        dummy_region = "us-test-1"
        aws_provider = set_mocked_aws_provider([dummy_region])
        # Create an SNS instance; override its topics to contain a dummy topic
        sns = SNS(aws_provider)
        # Override topics with a dummy topic for which get_topic_attributes will raise an exception
        dummy_topic = Topic(
            name="dummy",
            arn="arn:aws:sns:us-test-1:123456789012:dummy",
            region=dummy_region,
            policy=None,
            kms_master_key_id=None,
            tags=[],
        )
        sns.topics = [dummy_topic]

        # Create a fake regional client that always raises an exception in get_topic_attributes
        class FakeClient:
            region = dummy_region

            def get_topic_attributes(self, _):
                raise Exception("Test exception in get_topic_attributes")

        sns.regional_clients[dummy_region] = FakeClient()

        # Call the _get_topic_attributes method which should catch the exception
        sns._get_topic_attributes(sns.regional_clients)

        # Verify that the dummy topic's attributes have not been updated
        assert dummy_topic.policy is None
        assert dummy_topic.kms_master_key_id is None
        # Optionally, assert that the error message was logged
        assert "An error occurred" in caplog.text

    def test_list_subscriptions_by_topic_exception(self, caplog):
        """
        Test that SNS._list_subscriptions_by_topic gracefully handles exceptions raised by the regional client
        during subscription listing. The test ensures that if an exception is thrown, the topic's subscriptions
        remain empty and the error is logged.
        """
        # Create a dummy Topic for a fake "dummy-region"
        dummy_topic = Topic(
            name="dummy-sub",
            arn="arn:aws:sns:dummy-region:123456789012:dummy-sub",
            region="dummy-region",
            subscriptions=[],
        )

        # Create a fake regional client that always raises an exception when listing subscriptions.
        class FakeRegionalClient:
            region = "dummy-region"

            def list_subscriptions_by_topic(self, _):
                raise Exception("Test exception in list_subscriptions_by_topic")

        # Create an AWS provider with the dummy region and initialize SNS.
        aws_provider = set_mocked_aws_provider(["dummy-region"])
        sns = SNS(aws_provider)

        # Override topics and regional_clients with our dummy ones.
        sns.topics = [dummy_topic]
        sns.regional_clients["dummy-region"] = FakeRegionalClient()

        # Call _list_subscriptions_by_topic; the fake client should cause an exception.
        sns._list_subscriptions_by_topic()

        # Verify that due to the exception, the subscriptions for the dummy topic remain an empty list.
        assert dummy_topic.subscriptions == []
        # Also verify that the exception message was logged.
        assert "An error occurred" in caplog.text

    def test_get_topic_attributes_no_policy_no_kms(self):
        """
        Test that SNS._get_topic_attributes does not update a topic's policy or kms_master_key_id
        if the response Attributes do not include 'Policy' or 'KmsMasterKeyId'.
        """
        # Set up a dummy region and AWS provider
        dummy_region = "us-test-2"
        aws_provider = set_mocked_aws_provider([dummy_region])
        sns = SNS(aws_provider)

        # Create a dummy topic with no policy or kms_master_key_id
        dummy_topic = Topic(
            name="dummy-no-details",
            arn=f"arn:aws:sns:{dummy_region}:123456789012:dummy-no-details",
            region=dummy_region,
            policy=None,
            kms_master_key_id=None,
            tags=[],
        )
        # Override topics with our dummy topic
        sns.topics = [dummy_topic]

        # Create a fake regional client that returns attributes without 'Policy' and 'KmsMasterKeyId'
        class FakeNoDetailClient:
            region = dummy_region

            def get_topic_attributes(self, _):
                return {"Attributes": {"Dummy": "value"}}

        sns.regional_clients[dummy_region] = FakeNoDetailClient()

        # Call _get_topic_attributes which should read the attributes and update nothing
        sns._get_topic_attributes(sns.regional_clients)

        # Confirm that no changes were made to the topic's policy or kms_master_key_id
        assert dummy_topic.policy is None
        assert dummy_topic.kms_master_key_id is None

    def test_list_subscriptions_by_topic_unknown_region(self):
        """
        Test that SNS._list_subscriptions_by_topic correctly assigns 'unknown'
        to a subscription's region when the SubscriptionArn does not include enough parts.
        This verifies the fallback when the ARN format does not match the expected format.
        """
        # Create a dummy topic with a fake arn and region
        dummy_topic = Topic(
            name="dummy-unknown",
            arn="arn:aws:sns:dummy-region:123456789012:dummy-unknown",
            region="dummy-region",
            subscriptions=[],
        )

        # Create a fake regional client that returns a subscription with a poorly formatted ARN.
        class FakeRegionalClient:
            region = "dummy-region"

            def list_subscriptions_by_topic(self, _):
                # Return a subscription whose ARN doesn't include colon separators.
                return {
                    "Subscriptions": [
                        {
                            "SubscriptionArn": "badformatarn",  # Splitting will yield one element.
                            "Owner": "owner_dummy",
                            "Protocol": "smtp",
                            "Endpoint": "smtp://endpoint.example.com",
                        }
                    ]
                }

        # Set up an SNS instance with a dummy provider.
        from tests.providers.aws.utils import set_mocked_aws_provider

        aws_provider = set_mocked_aws_provider(["dummy-region"])
        sns = SNS(aws_provider)

        # Override topics and the regional client for the dummy-region with our fake ones.
        sns.topics = [dummy_topic]
        sns.regional_clients["dummy-region"] = FakeRegionalClient()

        # Call _list_subscriptions_by_topic which should process our fake subscription.
        sns._list_subscriptions_by_topic()

        # Verify that the subscription's region is set to "unknown" due to unexpected ARN format.
        assert len(dummy_topic.subscriptions) == 1
        subscription = dummy_topic.subscriptions[0]
        assert subscription.region == "unknown"
        assert subscription.protocol == "smtp"
        assert subscription.endpoint == "smtp://endpoint.example.com"

    def test_list_topics_with_audit_resources_filter(self, monkeypatch):
        """
        Test that when audit_resources is provided and the resource filtering function returns False,
        _list_topics does not add the topic to the topics list.
        """
        # Define a fake paginator that returns one topic.
        monkey_region = "us-fake-1"
        fake_topic_arn = f"arn:aws:sns:{monkey_region}:123456789012:dummy-topic"

        def fake_get_paginator(self, operation_name):
            class FakePaginator:
                def paginate(_):
                    return [{"Topics": [{"TopicArn": fake_topic_arn}]}]

            return FakePaginator()

        # Set up a provider with our fake region.
        aws_provider = set_mocked_aws_provider([monkey_region])
        # Create the SNS instance.
        sns = SNS(aws_provider)
        # To ensure a controlled test, clear any topics that may have been added in __init__
        sns.topics = []
        # Set audit_resources to a non-empty value to trigger the filtering logic.
        sns.audit_resources = ["some-non-empty-filter"]

        # Patch the fake regional client's get_paginator to our fake_get_paginator.
        fake_client = sns.regional_clients[monkey_region]
        fake_client.get_paginator = fake_get_paginator.__get__(
            fake_client, type(fake_client)
        )

        # Patch is_resource_filtered to always return False so that the topic is considered not filtered.
        with patch(
            "prowler.providers.aws.services.sns.sns_service.is_resource_filtered",
            return_value=False,
        ):
            sns._list_topics(fake_client)

        # Verify that the topic with name "dummy-topic" was not added to sns.topics.
        filtered_topics = [t for t in sns.topics if t.name == "dummy-topic"]
        assert filtered_topics == []


def test_list_topics_with_audit_resources_filter(monkeypatch):
    """
    Test that when audit_resources is provided and the resource filtering function returns False,
    _list_topics does not add the topic to the topics list.
    """
    # Define the fake region and topic ARN.
    monkey_region = "us-fake-1"
    fake_topic_arn = f"arn:aws:sns:{monkey_region}:123456789012:dummy-topic"

    # Define a fake paginator that returns one topic.
    def fake_get_paginator(operation_name):
        class FakePaginator:
            def paginate(_):
                return [{"Topics": [{"TopicArn": fake_topic_arn}]}]

        return FakePaginator()

    # Define a fake regional client with the required methods.
    class FakeRegionalClient:
        def __init__(self, region):
            self.region = region

        def get_paginator(self, operation_name):
            return fake_get_paginator(operation_name)

        def get_topic_attributes(self, _):
            # Returning empty Attributes dict to mimic no extra data.
            return {"Attributes": {}}

        def list_tags_for_resource(self, _):
            return {"Tags": []}

        def list_subscriptions_by_topic(self, _):
            return {"Subscriptions": []}

    # Create a fake regional client for the monkey_region.
    fake_client = FakeRegionalClient(monkey_region)

    # Create a fake provider with a regional_clients dictionary.
    fake_provider = SimpleNamespace(regional_clients={monkey_region: fake_client})

    # Create the SNS instance with the fake provider.
    sns = SNS(fake_provider)
    # Clear any topics that may have been added during __init__
    sns.topics = []
    # Set audit_resources so that filtering logic is active.
    sns.audit_resources = ["some-non-empty-filter"]

    # Patch the fake regional client's get_paginator to our fake_get_paginator method.
    monkeypatch.setattr(fake_client, "get_paginator", fake_get_paginator)

    # Patch is_resource_filtered to always return False so that the topic is considered filtered out.
    with patch(
        "prowler.providers.aws.services.sns.sns_service.is_resource_filtered",
        return_value=False,
    ):
        sns._list_topics(fake_client)

    # Verify that the topic with name "dummy-topic" was not added to sns.topics.
    filtered_topics = [t for t in sns.topics if t.name == "dummy-topic"]
    assert filtered_topics == []
