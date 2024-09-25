from enum import Enum

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class NetworkFirewall(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__("network-firewall", provider)
        self.network_firewalls = {}
        self.__threading_call__(self._list_firewalls)
        self._describe_firewall()
        self._describe_logging_configuration()

    def _list_firewalls(self, regional_client):
        logger.info("Network Firewall - Listing Network Firewalls...")
        try:
            list_network_firewalls_paginator = regional_client.get_paginator(
                "list_firewalls"
            )
            for page in list_network_firewalls_paginator.paginate():
                for network_firewall in page["Firewalls"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            network_firewall["FirewallArn"], self.audit_resources
                        )
                    ):
                        self.network_firewalls[
                            network_firewall.get("FirewallArn", "")
                        ] = Firewall(
                            region=regional_client.region,
                            name=network_firewall.get("FirewallName"),
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_firewall(self):
        logger.info("Network Firewall - Describe Network Firewalls...")
        try:
            for arn, network_firewall in self.network_firewalls.items():
                regional_client = self.regional_clients[network_firewall.region]
                try:
                    describe_firewall = regional_client.describe_firewall(
                        FirewallArn=arn,
                    )["Firewall"]
                    network_firewall.policy_arn = describe_firewall.get(
                        "FirewallPolicyArn"
                    )
                    network_firewall.vpc_id = describe_firewall.get("VpcId")
                    network_firewall.tags = describe_firewall.get("Tags", [])
                    encryption_config = describe_firewall.get(
                        "EncryptionConfiguration", {}
                    )
                    network_firewall.encryption_type = encryption_config.get("Type")
                    network_firewall.deletion_protection = describe_firewall.get(
                        "DeleteProtection", False
                    )
                except Exception as error:
                    logger.error(
                        f"Error describing firewall {network_firewall.arn} in region {network_firewall.region}: "
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def _describe_logging_configuration(self):
        logger.info(
            "Network Firewall - Describe Network Firewalls Logging Configuration..."
        )
        try:
            for arn, network_firewall in self.network_firewalls.items():
                describe_logging_configuration = (
                    self.regional_clients[network_firewall.region]
                    .describe_logging_configuration(FirewallArn=arn)
                    .get("LoggingConfiguration", {})
                )
                destination_configs = describe_logging_configuration.get(
                    "LogDestinationConfigs", []
                )
                network_firewall.logging_configuration = []
                if destination_configs:
                    for log_destination_config in destination_configs:
                        log_type = LogType(
                            log_destination_config.get("LogType", "FLOW")
                        )
                        log_destination_type = LogDestinationType(
                            log_destination_config.get("LogDestinationType", "S3")
                        )
                        log_destination = log_destination_config.get(
                            "LogDestination", {}
                        ).get(
                            "bucket-name"
                            if log_destination_type == LogDestinationType.s3
                            else (
                                "logGroup"
                                if log_destination_type
                                == LogDestinationType.cloudwatch_logs
                                else (
                                    "deliveryStream"
                                    if log_destination_type
                                    == LogDestinationType.kinesis_data_firehose
                                    else ""
                                )
                            )
                        )
                        network_firewall.logging_configuration.append(
                            LoggingConfiguration(
                                log_type=log_type,
                                log_destination_type=log_destination_type,
                                log_destination=log_destination,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )


class LogType(Enum):
    """Log Type for Network Firewall"""

    alert = "ALERT"
    flow = "FLOW"
    tls = "TLS"


class LogDestinationType(Enum):
    """Log Destination Type for Network Firewall"""

    s3 = "S3"
    cloudwatch_logs = "CloudWatchLogs"
    kinesis_data_firehose = "KinesisDataFirehose"


class LoggingConfiguration(BaseModel):
    """Logging Configuration for Network Firewall"""

    log_type: LogType
    log_destination_type: LogDestinationType
    log_destination: str = ""


class Firewall(BaseModel):
    """Firewall Model for Network Firewall"""

    name: str
    region: str
    policy_arn: str = None
    vpc_id: str = None
    tags: list = []
    encryption_type: str = None
    deletion_protection: bool = False
    logging_configuration: list[LoggingConfiguration] = []
