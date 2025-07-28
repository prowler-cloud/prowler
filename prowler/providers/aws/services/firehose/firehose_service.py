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

            stream.delivery_stream_type = describe_stream.get(
                "DeliveryStreamDescription", {}
            ).get("DeliveryStreamType", "")

            source_config = describe_stream.get("DeliveryStreamDescription", {}).get(
                "Source", {}
            )
            stream.source = Source(
                direct_put=DirectPutSourceDescription(
                    troughput_hint_in_mb_per_sec=source_config.get(
                        "DirectPutSourceDescription", {}
                    ).get("TroughputHintInMBPerSec", 0)
                ),
                kinesis_stream=KinesisStreamSourceDescription(
                    kinesis_stream_arn=source_config.get(
                        "KinesisStreamSourceDescription", {}
                    ).get("KinesisStreamARN", "")
                ),
                msk=MSKSourceDescription(
                    msk_cluster_arn=source_config.get("MSKSourceDescription", {}).get(
                        "MSKClusterARN", ""
                    )
                ),
                database=DatabaseSourceDescription(
                    endpoint=source_config.get("DatabaseSourceDescription", {}).get(
                        "Endpoint", ""
                    )
                ),
            )
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


class DirectPutSourceDescription(BaseModel):
    """Model for the DirectPut source of a Firehose stream"""

    troughput_hint_in_mb_per_sec: int = Field(default_factory=int)


class KinesisStreamSourceDescription(BaseModel):
    """Model for the KinesisStream source of a Firehose stream"""

    kinesis_stream_arn: str = Field(default_factory=str)


class MSKSourceDescription(BaseModel):
    """Model for the MSK source of a Firehose stream"""

    msk_cluster_arn: str = Field(default_factory=str)


class DatabaseSourceDescription(BaseModel):
    """Model for the Database source of a Firehose stream"""

    endpoint: str = Field(default_factory=str)


class Source(BaseModel):
    """Model for the source of a Firehose stream"""

    direct_put: Optional[DirectPutSourceDescription]
    kinesis_stream: Optional[KinesisStreamSourceDescription]
    msk: Optional[MSKSourceDescription]
    database: Optional[DatabaseSourceDescription]


class DeliveryStream(BaseModel):
    """Model for a Firehose Delivery Stream"""

    arn: str
    name: str
    region: str
    kms_key_arn: Optional[str] = Field(default_factory=str)
    kms_encryption: Optional[str] = Field(default_factory=str)
    tags: Optional[List[Dict[str, str]]] = Field(default_factory=list)
    delivery_stream_type: Optional[str] = Field(default_factory=str)
    source: Source = Field(default_factory=Source)
