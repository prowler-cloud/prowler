import threading
from json import loads

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################################ SNS
class SNS:
    def __init__(self, audit_info):
        self.service = "sns"
        self.session = audit_info.audit_session
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.topics = []
        self.__threading_call__(self.__list_topics__)
        self.__get_topic_attributes__(self.regional_clients)

    def __get_session__(self):
        return self.session

    def __threading_call__(self, call):
        threads = []
        for regional_client in self.regional_clients.values():
            threads.append(threading.Thread(target=call, args=(regional_client,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __list_topics__(self, regional_client):
        logger.info("SNS - listing topics...")
        try:
            list_topics_paginator = regional_client.get_paginator("list_topics")
            for page in list_topics_paginator.paginate():
                for topic_arn in page["Topics"]:
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


class Topic(BaseModel):
    name: str
    arn: str
    region: str
    policy: dict = None
    kms_master_key_id: str = None
