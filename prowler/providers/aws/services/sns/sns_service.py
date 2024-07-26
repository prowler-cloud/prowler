from json import loads
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################################ SNS
class SNS(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.topics = []
        self.__threading_call__(self.__list_topics__)
        self.__get_topic_attributes__(self.regional_clients)
        self.__list_tags_for_resource__()
        self.__list_subscriptions_by_topic__()

    def __list_topics__(self, regional_client):
        logger.info("SNS - listing topics...")
        try:
            list_topics_paginator = regional_client.get_paginator("list_topics")
            for page in list_topics_paginator.paginate():
                for topic_arn in page["Topics"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            topic_arn["TopicArn"], self.audit_resources
                        )
                    ):
                        self.topics.append(
                            Topic(
                                name=topic_arn["TopicArn"].rsplit(":", 1)[1],
                                arn=topic_arn["TopicArn"],
                                region=regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_topic_attributes__(self, regional_clients):
        logger.info("SNS - getting topic attributes...")
        try:
            for topic in self.topics:
                regional_client = regional_clients[topic.region]
                topic_attributes = regional_client.get_topic_attributes(
                    TopicArn=topic.arn
                )
                if "Policy" in topic_attributes["Attributes"]:
                    topic.policy = loads(topic_attributes["Attributes"]["Policy"])
                if "KmsMasterKeyId" in topic_attributes["Attributes"]:
                    topic.kms_master_key_id = topic_attributes["Attributes"][
                        "KmsMasterKeyId"
                    ]
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_tags_for_resource__(self):
        logger.info("SNS - List Tags...")
        try:
            for topic in self.topics:
                regional_client = self.regional_clients[topic.region]
                response = regional_client.list_tags_for_resource(
                    ResourceArn=topic.arn
                )["Tags"]
                topic.tags = response
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_subscriptions_by_topic__(self):
        logger.info("SNS - Listing subscriptions by topic...")
        try:
            for topic in self.topics:
                try:
                    regional_client = self.regional_clients[topic.region]
                    response = regional_client.list_subscriptions_by_topic(
                        TopicArn=topic.arn
                    )
                    subscriptions: list[Subscription] = [
                        Subscription(
                            id=sub["SubscriptionArn"].split(":")[-1],
                            arn=sub["SubscriptionArn"],
                            owner=sub["Owner"],
                            protocol=sub["Protocol"],
                            endpoint=sub["Endpoint"],
                        )
                        for sub in response["Subscriptions"]
                    ]
                    topic.subscriptions = subscriptions
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Subscription(BaseModel):
    id: str
    arn: str
    owner: str
    protocol: str
    endpoint: str


class Topic(BaseModel):
    name: str
    arn: str
    region: str
    policy: dict = None
    kms_master_key_id: str = None
    tags: Optional[list] = []
    subscriptions: Optional[list[Subscription]] = []
