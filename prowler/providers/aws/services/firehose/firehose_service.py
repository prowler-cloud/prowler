from enum import Enum
from typing import Dict, List, Optional

from botocore.client import ClientError
from pydantic.v1 import BaseModel, Field

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Firehose(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.delivery_streams = {}
        self.__threading_call__(self._list_delivery_streams)
        self.__threading_call__(
            self._list_tags_for_delivery_stream, self.delivery_streams.values()
        )
        self.__threading_call__(
            self._describe_delivery_stream, self.delivery_streams.values()
        )

    def _list_delivery_streams(self, regional_client):
        logger.info("Firehose - Listing delivery streams...")
        try:
            # Manual pagination using ExclusiveStartDeliveryStreamName
            # This ensures we get all streams alphabetically without duplicates
            exclusive_start_delivery_stream_name = None
            processed_streams = set()

            while True:
                kwargs = {}
                if exclusive_start_delivery_stream_name:
                    kwargs["ExclusiveStartDeliveryStreamName"] = (
                        exclusive_start_delivery_stream_name
                    )

                response = regional_client.list_delivery_streams(**kwargs)
                stream_names = response.get("DeliveryStreamNames", [])

                for stream_name in stream_names:
                    if stream_name in processed_streams:
                        continue

                    processed_streams.add(stream_name)
                    stream_arn = f"arn:{self.audited_partition}:firehose:{regional_client.region}:{self.audited_account}:deliverystream/{stream_name}"

                    if not self.audit_resources or (
                        is_resource_filtered(stream_arn, self.audit_resources)
                    ):
                        self.delivery_streams[stream_arn] = DeliveryStream(
                            arn=stream_arn,
                            name=stream_name,
                            region=regional_client.region,
                        )

                if not response.get("HasMoreDeliveryStreams", False):
                    break

                # Set the starting point for the next page (last stream name from current batch)
                # ExclusiveStartDeliveryStreamName will start after this stream alphabetically
                if stream_names:
                    exclusive_start_delivery_stream_name = stream_names[-1]
                else:
                    break

        except ClientError as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_delivery_stream(self, stream):
        logger.info(f"Firehose - Listing tags for stream {stream.name}...")
        try:
            stream.tags = (
                self.regional_clients[stream.region]
                .list_tags_for_delivery_stream(DeliveryStreamName=stream.name)
                .get("Tags", [])
            )
        except ClientError as error:
            logger.error(
                f"{stream.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_delivery_stream(self, stream):
        logger.info(f"Firehose - Describing stream {stream.name}...")
        try:
            describe_stream = self.regional_clients[
                stream.region
            ].describe_delivery_stream(DeliveryStreamName=stream.name)
            encryption_config = describe_stream.get(
                "DeliveryStreamDescription", {}
            ).get("DeliveryStreamEncryptionConfiguration", {})
            stream.kms_encryption = EncryptionStatus(
                encryption_config.get("Status", "DISABLED")
            )
            stream.kms_key_arn = encryption_config.get("KeyARN", "")
        except ClientError as error:
            logger.error(
                f"{stream.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class EncryptionStatus(Enum):
    """Possible values for the status of the encryption of a Firehose stream"""

    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    ENABLING = "ENABLING"
    DISABLING = "DISABLING"
    ENABLING_FAILED = "ENABLING_FAILED"
    DISABLING_FAILED = "DISABLING_FAILED"


class DeliveryStream(BaseModel):
    """Model for a Firehose Delivery Stream"""

    arn: str
    name: str
    region: str
    kms_key_arn: Optional[str] = Field(default_factory=str)
    kms_encryption: Optional[str] = Field(default_factory=str)
    tags: Optional[List[Dict[str, str]]] = Field(default_factory=list)
