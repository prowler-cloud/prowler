from typing import Dict, List, Optional

from botocore.client import ClientError
from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Firehose(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.delivery_streams = {}
        self.tags = []
        self.__threading_call__(self._list_delivery_streams)
        self.__threading_call__(
            self._list_tags_for_delivery_stream, self.delivery_streams.values()
        )

    def _list_delivery_streams(self, regional_client):
        logger.info("Firehose - Listing delivery streams...")
        try:
            for stream in regional_client.list_delivery_streams()[
                "DeliveryStreamNames"
            ]:
                if not self.audit_resources or (
                    is_resource_filtered(stream, self.audit_resources)
                ):
                    stream_region = regional_client.region
                    stream_arn = f"arn:{self.audited_partition}:firehose:{stream_region}:{self.audited_account}:deliverystream/{stream}"
                    self.delivery_streams[stream_arn] = DeliveryStream(
                        arn=stream_arn,
                        name=stream,
                        region=stream_region,
                    )
        except ClientError as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_delivery_stream(self, stream):
        try:
            stream.tags = (
                self.regional_clients[stream.region]
                .list_tags_for_delivery_stream(DeliveryStreamName=stream.name)
                .get("Tags", [])
            )
            print(stream.tags)
        except ClientError as error:
            logger.error(
                f"{stream.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class DeliveryStream(BaseModel):
    arn: str
    name: str
    region: str
    tags: Optional[List[Dict[str, str]]] = Field(default_factory=list)
