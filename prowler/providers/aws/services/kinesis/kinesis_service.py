from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Kinesis(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.streams = {}
        self.__threading_call__(self._list_streams)
        self.__threading_call__(self._describe_stream, self.streams.values())
        self.__threading_call__(self._list_tags_for_stream, self.streams.values())

    def _list_streams(self, regional_client):
        logger.info("Kinesis - Listing Kinesis Streams...")
        try:
            list_streams_paginator = regional_client.get_paginator("list_streams")
            for page in list_streams_paginator.paginate():
                for stream in page["StreamSummaries"]:
                    arn = stream["StreamARN"]
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        self.streams[arn] = Stream(
                            arn=arn,
                            name=stream["StreamName"],
                            region=regional_client.region,
                            status=StreamStatus(stream.get("StreamStatus", "ACTIVE")),
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_stream(self, stream):
        logger.info(f"Kinesis - Describing Stream {stream.name}...")
        try:
            stream_description = (
                self.regional_clients[stream.region]
                .describe_stream(StreamName=stream.name)
                .get("StreamDescription", {})
            )
            stream.encrypted_at_rest = EncryptionType(
                stream_description.get("EncryptionType", "NONE")
            )
            stream.retention_period = stream_description.get("RetentionPeriodHours", 24)
        except Exception as error:
            logger.error(
                f"{stream.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_stream(self, stream):
        logger.info(f"Kinesis - Listing tags for Stream {stream.name}...")
        try:
            stream.tags = (
                self.regional_clients[stream.region]
                .list_tags_for_stream(StreamName=stream.name)
                .get("Tags", [])
            )
        except Exception as error:
            logger.error(
                f"{stream.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class EncryptionType(Enum):
    """Enum for Kinesis Stream Encryption Type"""

    NONE = "NONE"
    KMS = "KMS"


class StreamStatus(Enum):
    """Enum for Kinesis Stream Status"""

    ACTIVE = "ACTIVE"
    CREATING = "CREATING"
    DELETING = "DELETING"
    UPDATING = "UPDATING"


class Stream(BaseModel):
    """Model for Kinesis Stream"""

    arn: str
    region: str
    name: str
    status: StreamStatus
    tags: Optional[List[Dict[str, str]]] = Field(default_factory=list)
    encrypted_at_rest: EncryptionType = EncryptionType.NONE
    retention_period: int = 24  # 1 day
