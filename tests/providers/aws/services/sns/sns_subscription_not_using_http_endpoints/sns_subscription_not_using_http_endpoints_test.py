from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.sns.sns_service import Subscription, Topic
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

kms_key_id = str(uuid4())
topic_name = "test-topic"
topic_arn = f"arn:aws:sns:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:{topic_name}"
subscription_id_1 = str(uuid4())
subscription_id_2 = str(uuid4())
subscription_arn_1 = f"{topic_arn}:{subscription_id_1}"
subscription_arn_2 = f"{topic_arn}:{subscription_id_2}"


class Test_sns_subscription_not_using_http_endpoints:
    def test_no_topics(self):
        sns_client = mock.MagicMock
        sns_client.topics = []
        with mock.patch(
            "prowler.providers.aws.services.sns.sns_service.SNS",
            sns_client,
        ):
            from prowler.providers.aws.services.sns.sns_subscription_not_using_http_endpoints.sns_subscription_not_using_http_endpoints import (
                sns_subscription_not_using_http_endpoints,
            )

            check = sns_subscription_not_using_http_endpoints()
            result = check.execute()
            assert len(result) == 0

    def test_no_subscriptions(self):
        sns_client = mock.MagicMock
        subscriptions = []
        sns_client.topics = []
        sns_client.topics.append(
            Topic(
                arn=topic_arn,
                name=topic_name,
                kms_master_key_id=kms_key_id,
                region=AWS_REGION_EU_WEST_1,
                subscriptions=subscriptions,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.sns.sns_service.SNS",
            sns_client,
        ):
            from prowler.providers.aws.services.sns.sns_subscription_not_using_http_endpoints.sns_subscription_not_using_http_endpoints import (
                sns_subscription_not_using_http_endpoints,
            )

            check = sns_subscription_not_using_http_endpoints()
            result = check.execute()
            assert len(result) == 0

    def test_subscriptions_with_pending_confirmation(self):
        sns_client = mock.MagicMock
        subscriptions = []
        subscriptions.append(
            Subscription(
                id="PendingConfirmation",
                arn="PendingConfirmation",
                owner=AWS_ACCOUNT_NUMBER,
                protocol="https",
                endpoint="https://www.endpoint.com",
            )
        )
        sns_client.topics = []
        sns_client.topics.append(
            Topic(
                arn=topic_arn,
                name=topic_name,
                kms_master_key_id=kms_key_id,
                region=AWS_REGION_EU_WEST_1,
                subscriptions=subscriptions,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.sns.sns_service.SNS",
            sns_client,
        ):
            from prowler.providers.aws.services.sns.sns_subscription_not_using_http_endpoints.sns_subscription_not_using_http_endpoints import (
                sns_subscription_not_using_http_endpoints,
            )

            check = sns_subscription_not_using_http_endpoints()
            result = check.execute()
            assert len(result) == 0

    def test_subscriptions_with_https(self):
        sns_client = mock.MagicMock
        subscriptions = []
        subscriptions.append(
            Subscription(
                id=subscription_id_1,
                arn=subscription_arn_1,
                owner=AWS_ACCOUNT_NUMBER,
                protocol="https",
                endpoint="https://www.endpoint.com",
            )
        )
        sns_client.topics = []
        sns_client.topics.append(
            Topic(
                arn=topic_arn,
                name=topic_name,
                kms_master_key_id=kms_key_id,
                region=AWS_REGION_EU_WEST_1,
                subscriptions=subscriptions,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.sns.sns_service.SNS",
            sns_client,
        ):
            from prowler.providers.aws.services.sns.sns_subscription_not_using_http_endpoints.sns_subscription_not_using_http_endpoints import (
                sns_subscription_not_using_http_endpoints,
            )

            check = sns_subscription_not_using_http_endpoints()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Subscription {subscription_arn_1} is using an HTTPS endpoint."
            )
            assert result[0].resource_id == subscription_id_1
            assert result[0].resource_arn == subscription_arn_1

    def test_subscriptions_with_http(self):
        sns_client = mock.MagicMock
        subscriptions = []
        subscriptions.append(
            Subscription(
                id=subscription_id_2,
                arn=subscription_arn_2,
                owner=AWS_ACCOUNT_NUMBER,
                protocol="http",
                endpoint="http://www.endpoint.com",
            )
        )
        sns_client.topics = []
        sns_client.topics.append(
            Topic(
                arn=topic_arn,
                name=topic_name,
                kms_master_key_id=kms_key_id,
                region=AWS_REGION_EU_WEST_1,
                subscriptions=subscriptions,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.sns.sns_service.SNS",
            sns_client,
        ):
            from prowler.providers.aws.services.sns.sns_subscription_not_using_http_endpoints.sns_subscription_not_using_http_endpoints import (
                sns_subscription_not_using_http_endpoints,
            )

            check = sns_subscription_not_using_http_endpoints()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Subscription {subscription_arn_2} is using an HTTP endpoint."
            )
            assert result[0].resource_id == subscription_id_2
            assert result[0].resource_arn == subscription_arn_2

    def test_subscriptions_with_http_and_https(self):
        sns_client = mock.MagicMock
        subscriptions = []
        subscriptions.append(
            Subscription(
                id=subscription_id_1,
                arn=subscription_arn_1,
                owner=AWS_ACCOUNT_NUMBER,
                protocol="https",
                endpoint="https://www.endpoint.com",
            )
        )
        subscriptions.append(
            Subscription(
                id=subscription_id_2,
                arn=subscription_arn_2,
                owner=AWS_ACCOUNT_NUMBER,
                protocol="http",
                endpoint="http://www.endpoint.com",
            )
        )
        sns_client.topics = []
        sns_client.topics.append(
            Topic(
                arn=topic_arn,
                name=topic_name,
                kms_master_key_id=kms_key_id,
                region=AWS_REGION_EU_WEST_1,
                subscriptions=subscriptions,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.sns.sns_service.SNS",
            sns_client,
        ):
            from prowler.providers.aws.services.sns.sns_subscription_not_using_http_endpoints.sns_subscription_not_using_http_endpoints import (
                sns_subscription_not_using_http_endpoints,
            )

            check = sns_subscription_not_using_http_endpoints()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Subscription {subscription_arn_1} is using an HTTPS endpoint."
            )
            assert result[0].resource_id == subscription_id_1
            assert result[0].resource_arn == subscription_arn_1

            assert result[1].status == "FAIL"
            assert (
                result[1].status_extended
                == f"Subscription {subscription_arn_2} is using an HTTP endpoint."
            )
            assert result[1].resource_id == subscription_id_2
            assert result[1].resource_arn == subscription_arn_2
