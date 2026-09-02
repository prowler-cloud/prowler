from types import SimpleNamespace
from unittest import mock

from prowler.providers.huaweicloud.services.smn.smn_service import SMN


def _topic(number: int):
    return SimpleNamespace(
        topic_urn=f"urn:smn:eu-west-101:account:topic-{number}",
        topic_id=f"topic-{number}",
        name=f"topic-{number}",
        display_name=f"Topic {number}",
        push_policy=0,
    )


def _service(client):
    service = SMN.__new__(SMN)
    service.regional_clients = {"eu-west-101": client}
    service.topics = []
    return service


class TestHuaweiCloudSMNService:
    def test_unconfirmed_and_canceled_subscriptions_do_not_count(self):
        client = mock.MagicMock()
        client.list_topics.return_value = SimpleNamespace(
            topic_count=1, topics=[_topic(1)]
        )
        client.list_subscriptions_by_topic.return_value = SimpleNamespace(
            subscription_count=2,
            subscriptions=[
                SimpleNamespace(status=0),
                SimpleNamespace(status=3),
            ],
        )
        service = _service(client)

        service._list_topics()

        assert len(service.topics) == 1
        assert service.topics[0].confirmed_subscription_count == 0

    def test_paginates_topics_and_confirmed_subscriptions(self):
        client = mock.MagicMock()
        first_page_subscriptions = [SimpleNamespace(status=0) for _ in range(100)]
        client.list_topics.side_effect = [
            SimpleNamespace(topic_count=101, topics=[_topic(1)]),
            SimpleNamespace(topic_count=101, topics=[_topic(2)]),
        ]
        client.list_subscriptions_by_topic.side_effect = [
            SimpleNamespace(
                subscription_count=101, subscriptions=first_page_subscriptions
            ),
            SimpleNamespace(
                subscription_count=101,
                subscriptions=[SimpleNamespace(status=1)],
            ),
            SimpleNamespace(
                subscription_count=2,
                subscriptions=[
                    SimpleNamespace(status=1),
                    SimpleNamespace(status=3),
                ],
            ),
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
        client.list_topics.return_value = SimpleNamespace(
            topic_count=1, topics=[_topic(1)]
        )
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

    def test_real_session_does_not_require_is_mock_attribute(self):
        provider = mock.MagicMock()

        def initialize_service(service, *_args, **_kwargs):
            service.session = SimpleNamespace()

        with (
            mock.patch.object(SMN, "_list_topics") as list_topics,
            mock.patch(
                "prowler.providers.huaweicloud.services.smn.smn_service.HuaweiCloudService.__init__",
                new=initialize_service,
            ),
        ):
            SMN(provider)

        list_topics.assert_called_once_with()
