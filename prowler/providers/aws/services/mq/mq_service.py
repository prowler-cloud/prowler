from enum import Enum
from typing import Dict, List

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class MQ(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.brokers = {}
        self.__threading_call__(self._list_brokers)
        self.__threading_call__(self._describe_broker, self.brokers.values())

    def _list_brokers(self, regional_client):
        logger.info("MQ - Listing brokers...")
        try:
            for broker in regional_client.list_brokers()["BrokerSummaries"]:
                if not self.audit_resources or (
                    is_resource_filtered(broker["BrokerArn"], self.audit_resources)
                ):
                    broker_arn = broker["BrokerArn"]
                    self.brokers[broker_arn] = Broker(
                        arn=broker_arn,
                        name=broker["BrokerName"],
                        id=broker["BrokerId"],
                        region=regional_client.region,
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_broker(self, broker):
        try:
            describe_broker = self.regional_clients[broker.region].describe_broker(
                BrokerId=broker.id
            )
            broker.engine_type = EngineType(
                describe_broker.get("EngineType", "ACTIVEMQ").upper()
            )
            broker.deployment_mode = DeploymentMode(
                describe_broker.get("DeploymentMode", "SINGLE_INSTANCE").upper()
            )
            broker.auto_minor_version_upgrade = describe_broker.get(
                "AutoMinorVersionUpgrade", False
            )
            broker.general_logging_enabled = describe_broker.get("Logs", {}).get(
                "General", False
            )
            broker.audit_logging_enabled = describe_broker.get("Logs", {}).get(
                "Audit", False
            )
            broker.publicly_accessible = describe_broker.get(
                "PubliclyAccessible", False
            )
            broker.tags = [describe_broker.get("Tags", {})]

        except Exception as error:
            logger.error(
                f"{broker.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class DeploymentMode(Enum):
    """Possible Deployment Modes for MQ"""

    SINGLE_INSTANCE = "SINGLE_INSTANCE"
    ACTIVE_STANDBY_MULTI_AZ = "ACTIVE_STANDBY_MULTI_AZ"
    CLUSTER_MULTI_AZ = "CLUSTER_MULTI_AZ"


class EngineType(Enum):
    """Possible Engine Types for MQ"""

    ACTIVEMQ = "ACTIVEMQ"
    RABBITMQ = "RABBITMQ"


class Broker(BaseModel):
    """Broker model for MQ"""

    arn: str
    name: str
    id: str
    region: str
    auto_minor_version_upgrade: bool = Field(default=False)
    publicly_accessible: bool = Field(default=False)
    general_logging_enabled: bool = Field(default=False)
    audit_logging_enabled: bool = Field(default=False)
    engine_type: EngineType = EngineType.ACTIVEMQ
    deployment_mode: DeploymentMode = DeploymentMode.SINGLE_INSTANCE
    tags: List[Dict[str, str]] = Field(default_factory=list)
