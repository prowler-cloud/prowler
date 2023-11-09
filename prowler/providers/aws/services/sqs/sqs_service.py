from json import loads
from typing import Optional

from botocore.exceptions import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################################ SQS
class SQS(AWSService):
    def __init__(self, audit_info):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, audit_info)
        self.queues = []
        self.__threading_call__(self.__list_queues__)
        self.__get_queue_attributes__()
        self.__list_queue_tags__()

    def __list_queues__(self, regional_client):
        logger.info("SQS - describing queues...")
        try:
            list_queues_paginator = regional_client.get_paginator("list_queues")
            for page in list_queues_paginator.paginate():
                if "QueueUrls" in page:
                    for queue in page["QueueUrls"]:
                        # the queue name is the last path segment of the url
                        queue_name = queue.split("/")[-1]
                        arn = f"arn:{self.audited_partition}:sqs:{regional_client.region}:{self.audited_account}:{queue_name}"
                        if not self.audit_resources or (
                            is_resource_filtered(arn, self.audit_resources)
                        ):
                            self.queues.append(
                                Queue(
                                    arn=arn,
                                    name=queue_name,
                                    id=queue,
                                    region=regional_client.region,
                                )
                            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_queue_attributes__(self):
        try:
            logger.info("SQS - describing queue attributes...")
            for queue in self.queues:
                try:
                    regional_client = self.regional_clients[queue.region]
                    queue_attributes = regional_client.get_queue_attributes(
                        QueueUrl=queue.id, AttributeNames=["All"]
                    )
                    if "Attributes" in queue_attributes:
                        if "Policy" in queue_attributes["Attributes"]:
                            queue.policy = loads(
                                queue_attributes["Attributes"]["Policy"]
                            )
                        if "KmsMasterKeyId" in queue_attributes["Attributes"]:
                            queue.kms_key_id = queue_attributes["Attributes"][
                                "KmsMasterKeyId"
                            ]
                        if "SqsManagedSseEnabled" in queue_attributes["Attributes"]:
                            if (
                                queue_attributes["Attributes"]["SqsManagedSseEnabled"]
                                == "true"
                            ):
                                queue.kms_key_id = "SqsManagedSseEnabled"
                except ClientError as error:
                    if (
                        error.response["Error"]["Code"]
                        == "AWS.SimpleQueueService.NonExistentQueue"
                    ):
                        logger.warning(
                            f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                    else:
                        logger.error(
                            f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_queue_tags__(self):
        logger.info("SQS - List Tags...")
        try:
            for queue in self.queues:
                try:
                    regional_client = self.regional_clients[queue.region]
                    response = regional_client.list_queue_tags(QueueUrl=queue.id).get(
                        "Tags"
                    )
                    queue.tags = [response]
                except ClientError as error:
                    if (
                        error.response["Error"]["Code"]
                        == "AWS.SimpleQueueService.NonExistentQueue"
                    ):
                        logger.warning(
                            f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                    else:
                        logger.error(
                            f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Queue(BaseModel):
    id: str
    name: str
    arn: str
    region: str
    policy: dict = None
    kms_key_id: str = None
    tags: Optional[list] = []
