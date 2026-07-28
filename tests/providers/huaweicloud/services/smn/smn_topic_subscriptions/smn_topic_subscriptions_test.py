from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class Test_smn_topic_subscriptions:
    def test_no_topics(self):
        smn_client = mock.MagicMock()
        smn_client.topics = []
        smn_client.region = "la-south-2"
        smn_client.audited_account = "123456789012"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.smn.smn_topic_subscriptions.smn_topic_subscriptions.smn_client",
                new=smn_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.smn.smn_topic_subscriptions.smn_topic_subscriptions import (
                smn_topic_subscriptions,
            )

            check = smn_topic_subscriptions()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "No SMN topics are configured" in result[0].status_extended

    def test_topic_with_subscriptions(self):
        smn_client = mock.MagicMock()
        smn_client.topics = [
            mock.MagicMock(
                topic_urn="urn:smn:la-south-2:123456789012:alert-topic",
                topic_id="topic-001",
                name="alert-topic",
                display_name="Alert Topic",
                push_policy=0,
                subscription_count=2,
                region="la-south-2",
            )
        ]
        smn_client.region = "la-south-2"
        smn_client.audited_account = "123456789012"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.smn.smn_topic_subscriptions.smn_topic_subscriptions.smn_client",
                new=smn_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.smn.smn_topic_subscriptions.smn_topic_subscriptions import (
                smn_topic_subscriptions,
            )

            check = smn_topic_subscriptions()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "alert-topic" in result[0].status_extended
            assert "2" in result[0].status_extended

    def test_topic_without_subscriptions(self):
        smn_client = mock.MagicMock()
        smn_client.topics = [
            mock.MagicMock(
                topic_urn="urn:smn:la-south-2:123456789012:empty-topic",
                topic_id="topic-002",
                name="empty-topic",
                display_name="Empty Topic",
                push_policy=0,
                subscription_count=0,
                region="la-south-2",
            )
        ]
        smn_client.region = "la-south-2"
        smn_client.audited_account = "123456789012"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.smn.smn_topic_subscriptions.smn_topic_subscriptions.smn_client",
                new=smn_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.smn.smn_topic_subscriptions.smn_topic_subscriptions import (
                smn_topic_subscriptions,
            )

            check = smn_topic_subscriptions()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "empty-topic" in result[0].status_extended
            assert "no subscriptions" in result[0].status_extended

    def test_mixed_topics(self):
        smn_client = mock.MagicMock()
        smn_client.topics = [
            mock.MagicMock(
                topic_urn="urn:smn:la-south-2:123456789012:alert-topic",
                topic_id="topic-001",
                name="alert-topic",
                display_name="Alert Topic",
                push_policy=0,
                subscription_count=3,
                region="la-south-2",
            ),
            mock.MagicMock(
                topic_urn="urn:smn:la-south-2:123456789012:empty-topic",
                topic_id="topic-002",
                name="empty-topic",
                display_name="Empty Topic",
                push_policy=0,
                subscription_count=0,
                region="la-south-2",
            ),
        ]
        smn_client.region = "la-south-2"
        smn_client.audited_account = "123456789012"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.smn.smn_topic_subscriptions.smn_topic_subscriptions.smn_client",
                new=smn_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.smn.smn_topic_subscriptions.smn_topic_subscriptions import (
                smn_topic_subscriptions,
            )

            check = smn_topic_subscriptions()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "PASS"
            assert result[1].status == "FAIL"
