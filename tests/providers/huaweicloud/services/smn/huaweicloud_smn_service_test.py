from unittest import mock

from huaweicloudsdksmn.v2 import (
    ListSubscriptionsByTopicResponse,
    ListSubscriptionsItem,
    ListTopicsItem,
    ListTopicsResponse,
)

from prowler.providers.huaweicloud.services.smn.smn_service import SMN


def _topic(number: int) -> ListTopicsItem:
    return ListTopicsItem(
        topic_urn=f"urn:smn:eu-west-101:account:topic-{number}",
        topic_id=f"topic-{number}",
        name=f"topic-{number}",
        display_name=f"Topic {number}",
        push_policy=0,
    )


def _topics_page(topic_count: int, topics: list) -> ListTopicsResponse:
    return ListTopicsResponse(topic_count=topic_count, topics=topics)


def _subscriptions_page(
    subscription_count: int, statuses: list
) -> ListSubscriptionsByTopicResponse:
    return ListSubscriptionsByTopicResponse(
        subscription_count=subscription_count,
        subscriptions=[ListSubscriptionsItem(status=status) for status in statuses],
    )


def _service(client):
    service = SMN.__new__(SMN)
    service.regional_clients = {"eu-west-101": client}
    service.topics = []
    return service


class TestHuaweiCloudSMNService:
    def test_unconfirmed_and_canceled_subscriptions_do_not_count(self):
        client = mock.MagicMock()
        client.list_topics.return_value = _topics_page(1, [_topic(1)])
        client.list_subscriptions_by_topic.return_value = _subscriptions_page(2, [0, 3])
        service = _service(client)

        service._list_topics()

        assert len(service.topics) == 1
        assert service.topics[0].confirmed_subscription_count == 0

    def test_paginates_topics_and_confirmed_subscriptions(self):
        client = mock.MagicMock()
        client.list_topics.side_effect = [
            _topics_page(101, [_topic(1)]),
            _topics_page(101, [_topic(2)]),
        ]
        client.list_subscriptions_by_topic.side_effect = [
            _subscriptions_page(101, [0] * 100),
            _subscriptions_page(101, [1]),
            _subscriptions_page(2, [1, 3]),
        ]
        service = _service(client)

        service._list_topics()

        assert [topic.confirmed_subscription_count for topic in service.topics] == [
            1,
            1,
        ]
        topic_requests = [call.args[0] for call in client.list_topics.call_args_list]
        assert [(request.offset, request.limit) for request in topic_requests] == [
            (0, 100),
            (100, 100),
        ]
        subscription_requests = [
            call.args[0] for call in client.list_subscriptions_by_topic.call_args_list
        ]
        assert [
            (request.topic_urn, request.offset, request.limit)
            for request in subscription_requests
        ] == [
            ("urn:smn:eu-west-101:account:topic-1", 0, 100),
            ("urn:smn:eu-west-101:account:topic-1", 100, 100),
            ("urn:smn:eu-west-101:account:topic-2", 0, 100),
        ]

    def test_skips_topic_when_subscription_discovery_fails(self):
        client = mock.MagicMock()
        client.list_topics.return_value = _topics_page(1, [_topic(1)])
        client.list_subscriptions_by_topic.side_effect = Exception("denied")
        service = _service(client)

        service._list_topics()

        assert service.topics == []

    def test_topic_discovery_failure_returns_empty_inventory(self):
        client = mock.MagicMock()
        client.list_topics.side_effect = Exception("denied")
        service = _service(client)

        service._list_topics()

        assert service.topics == []

    def test_init_always_lists_topics_from_the_api(self):
        def initialize_service(service, *_args, **_kwargs):
            service.session = mock.MagicMock()

        with (
            mock.patch.object(SMN, "_list_topics") as list_topics,
            mock.patch(
                "prowler.providers.huaweicloud.services.smn.smn_service.HuaweiCloudService.__init__",
                new=initialize_service,
            ),
        ):
            service = SMN(mock.MagicMock())

        list_topics.assert_called_once_with()
        assert service.topics == []
