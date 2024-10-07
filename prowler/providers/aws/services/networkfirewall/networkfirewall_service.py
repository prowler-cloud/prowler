from enum import Enum
from typing import Optional

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
        self.__threading_call__(
            self._describe_firewall, self.network_firewalls.values()
        )
        self.__threading_call__(
            self._describe_firewall_policy, self.network_firewalls.values()
        )
        self.__threading_call__(
            self._describe_logging_configuration, self.network_firewalls.values()
        )

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
                        arn = network_firewall.get("FirewallArn", "")
                        self.network_firewalls[arn] = Firewall(
                            arn=network_firewall.get("FirewallArn"),
                            region=regional_client.region,
                            name=network_firewall.get("FirewallName"),
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_firewall(self, network_firewall):
        logger.info("Network Firewall - Describe Network Firewalls...")
        try:
            regional_client = self.regional_clients[network_firewall.region]
            describe_firewall = regional_client.describe_firewall(
                FirewallArn=network_firewall.arn,
            )["Firewall"]
            network_firewall.policy_arn = describe_firewall.get("FirewallPolicyArn")
            network_firewall.vpc_id = describe_firewall.get("VpcId")
            network_firewall.tags = describe_firewall.get("Tags", [])
            encryption_config = describe_firewall.get("EncryptionConfiguration", {})
            network_firewall.encryption_type = encryption_config.get("Type")
            network_firewall.deletion_protection = describe_firewall.get(
                "DeleteProtection", False
            )
            for subnet in describe_firewall.get("SubnetMappings", []):
                if subnet.get("SubnetId"):
                    network_firewall.subnet_mappings.append(
                        Subnet(
                            subnet_id=subnet.get("SubnetId"),
                            ip_addr_type=subnet.get(
                                "IPAddressType", IPAddressType.IPV4
                            ),
                        )
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def _describe_firewall_policy(self, network_firewall):
        logger.info("Network Firewall - Describe Network Firewall Policies...")
        try:
            regional_client = self.regional_clients[network_firewall.region]
            describe_firewall_policy = regional_client.describe_firewall_policy(
                FirewallPolicyArn=network_firewall.policy_arn,
            )
            firewall_policy = describe_firewall_policy.get("FirewallPolicy", {})
            network_firewall.stateless_rule_groups = [
                group.get("ResourceArn", "")
                for group in firewall_policy.get("StatelessRuleGroupReferences", [])
            ]
            network_firewall.stateful_rule_groups = [
                group.get("ResourceArn", "")
                for group in firewall_policy.get("StatefulRuleGroupReferences", [])
            ]
            network_firewall.default_stateless_actions = firewall_policy.get(
                "StatelessDefaultActions", []
            )
            network_firewall.default_stateless_frag_actions = firewall_policy.get(
                "StatelessFragmentDefaultActions", []
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def _describe_logging_configuration(self, network_firewall):
        logger.info(
            "Network Firewall - Describe Network Firewalls Logging Configuration..."
        )
        try:
            describe_logging_configuration = (
                self.regional_clients[network_firewall.region]
                .describe_logging_configuration(FirewallArn=network_firewall.arn)
                .get("LoggingConfiguration", {})
            )
            destination_configs = describe_logging_configuration.get(
                "LogDestinationConfigs", []
            )
            network_firewall.logging_configuration = []
            if destination_configs:
                for log_destination_config in destination_configs:
                    log_type = LogType(log_destination_config.get("LogType", "FLOW"))
                    log_destination_type = LogDestinationType(
                        log_destination_config.get("LogDestinationType", "S3")
                    )
                    log_destination = log_destination_config.get("LogDestination", {})
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
    log_destination: dict = {}


class IPAddressType(Enum):
    """Enum for IP Address Type"""

    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DUALSTACK = "DUALSTACK"


class Subnet(BaseModel):
    """Subnet model for SubnetMappings"""

    subnet_id: str
    ip_addr_type: IPAddressType


class Firewall(BaseModel):
    """Firewall Model for Network Firewall"""

    arn: str
    name: str
    region: str
    policy_arn: str = None
    vpc_id: str = None
    tags: list = []
    encryption_type: str = None
    deletion_protection: bool = False
    default_stateless_actions: list = []
    default_stateless_frag_actions: list = []
    subnet_mappings: list[Subnet] = []
    logging_configuration: Optional[list[LoggingConfiguration]]
    stateless_rule_groups: list[str] = []
    stateful_rule_groups: list[str] = []
