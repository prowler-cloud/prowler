from typing import List

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService

SMN_PAGE_SIZE = 100


class SMN(HuaweiCloudService):
    """
    SMN (Simple Message Notification) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud SMN service
    to retrieve notification topics and their subscription counts.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.topics: List[SMNTopic] = []

        if getattr(self.session, "is_mock", False):
            self._load_mock_data()
            return

        self._list_topics()

    def _load_mock_data(self):
        """Load mock data for testing."""
        region = "la-south-2"
        self.topics = [
            SMNTopic(
                topic_urn="urn:smn:la-south-2:123456789012:alert-topic",
                topic_id="topic-001",
                name="alert-topic",
                display_name="Alert Topic",
                push_policy=0,
                confirmed_subscription_count=2,
                region=region,
            ),
            SMNTopic(
                topic_urn="urn:smn:la-south-2:123456789012:empty-topic",
                topic_id="topic-002",
                name="empty-topic",
                display_name="Empty Topic",
                push_policy=0,
                confirmed_subscription_count=0,
                region=region,
            ),
        ]

    def _list_topics(self):
        """List all SMN topics across regions and get their subscription counts."""
        if not self.regional_clients:
            return

        for region, client in self.regional_clients.items():
            logger.info(f"SMN - Listing Topics in {region}...")

            try:
                from huaweicloudsdksmn.v2 import (
                    ListSubscriptionsByTopicRequest,
                    ListTopicsRequest,
                )

                offset = 0
                while True:
                    request = ListTopicsRequest(offset=offset, limit=SMN_PAGE_SIZE)
                    response = self._call_with_retries(client.list_topics, request)
                    topics = getattr(response, "topics", None) or []

                    for topic in topics:
                        topic_urn = getattr(topic, "topic_urn", "") or ""
                        topic_id = getattr(topic, "topic_id", "") or ""
                        name = getattr(topic, "name", "") or ""
                        display_name = getattr(topic, "display_name", "") or ""
                        push_policy = getattr(topic, "push_policy", None)

                        try:
                            confirmed_subscription_count = 0
                            subscription_offset = 0
                            while True:
                                sub_request = ListSubscriptionsByTopicRequest(
                                    topic_urn=topic_urn,
                                    offset=subscription_offset,
                                    limit=SMN_PAGE_SIZE,
                                )
                                sub_response = self._call_with_retries(
                                    client.list_subscriptions_by_topic, sub_request
                                )
                                subscriptions = (
                                    getattr(sub_response, "subscriptions", None) or []
                                )
                                confirmed_subscription_count += sum(
                                    getattr(subscription, "status", None) == 1
                                    for subscription in subscriptions
                                )
                                subscription_count = (
                                    getattr(sub_response, "subscription_count", 0) or 0
                                )
                                subscription_offset += SMN_PAGE_SIZE
                                if subscription_offset >= subscription_count:
                                    break
                        except Exception as sub_error:
                            logger.error(
                                f"{region} -- {sub_error.__class__.__name__}"
                                f"[{sub_error.__traceback__.tb_lineno}]: {sub_error}"
                            )
                            continue

                        self.topics.append(
                            SMNTopic(
                                topic_urn=topic_urn,
                                topic_id=topic_id,
                                name=name,
                                display_name=display_name,
                                push_policy=push_policy,
                                confirmed_subscription_count=confirmed_subscription_count,
                                region=region,
                            )
                        )

                    offset += SMN_PAGE_SIZE
                    topic_count = getattr(response, "topic_count", 0) or 0
                    if offset >= topic_count:
                        break

            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class SMNTopic(BaseModel):
    """SMN topic model."""

    topic_urn: str
    topic_id: str = ""
    name: str = ""
    display_name: str = ""
    push_policy: int = None
    confirmed_subscription_count: int = 0
    region: str = ""
