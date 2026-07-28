from typing import List

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class SMN(HuaweiCloudService):
    """
    SMN (Simple Message Notification) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud SMN service
    to retrieve notification topics and their subscription counts.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.topics: List[SMNTopic] = []

        if self.session.is_mock:
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
                subscription_count=2,
                region=region,
            ),
            SMNTopic(
                topic_urn="urn:smn:la-south-2:123456789012:empty-topic",
                topic_id="topic-002",
                name="empty-topic",
                display_name="Empty Topic",
                push_policy=0,
                subscription_count=0,
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
                    ListTopicsRequest,
                    ListSubscriptionsByTopicRequest,
                )

                request = ListTopicsRequest()
                response = self._call_with_retries(client.list_topics, request)

                if response and response.topics:
                    for topic in response.topics:
                        topic_urn = getattr(topic, "topic_urn", "") or ""
                        topic_id = getattr(topic, "topic_id", "") or ""
                        name = getattr(topic, "name", "") or ""
                        display_name = getattr(topic, "display_name", "") or ""
                        push_policy = getattr(topic, "push_policy", None)

                        subscription_count = 0
                        if topic_urn:
                            try:
                                sub_request = ListSubscriptionsByTopicRequest(
                                    topic_urn=topic_urn
                                )
                                sub_response = self._call_with_retries(
                                    client.list_subscriptions_by_topic, sub_request
                                )
                                if sub_response:
                                    subscription_count = getattr(
                                        sub_response, "subscription_count", 0
                                    ) or 0
                            except Exception as sub_error:
                                logger.error(
                                    f"{region} -- {sub_error.__class__.__name__}: {sub_error}"
                                )

                        self.topics.append(
                            SMNTopic(
                                topic_urn=topic_urn,
                                topic_id=topic_id,
                                name=name,
                                display_name=display_name,
                                push_policy=push_policy,
                                subscription_count=subscription_count,
                                region=region,
                            )
                        )

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
    subscription_count: int = 0
    region: str = ""
