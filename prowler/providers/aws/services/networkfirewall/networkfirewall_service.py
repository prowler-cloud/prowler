from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## NetworkFirewall
class NetworkFirewall(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__("network-firewall", provider)
        self.network_firewalls = {}
        self.__threading_call__(self._list_firewalls)
        self._describe_firewall()

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

    def _describe_firewall_policy(self):
        logger.info("Network Firewall - Describe Network Firewall Policies...")
        try:
            for network_firewall in self.network_firewalls.values():
                regional_client = self.regional_clients[network_firewall.region]
                try:
                    describe_firewall_policy = regional_client.describe_firewall_policy(
                        FirewallPolicyArn=network_firewall.policy_arn,
                    )
                    firewall_policy = describe_firewall_policy.get("FirewallPolicy", {})
                    network_firewall.default_stateless_actions = firewall_policy.get(
                        "StatelessDefaultActions", []
                    )
                except Exception as error:
                    logger.error(
                        f"Error describing firewall policy {network_firewall.policy_arn} in region {network_firewall.region}: "
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )


class Firewall(BaseModel):
    name: str
    region: str
    policy_arn: str = None
    vpc_id: str = None
    tags: list = []
    encryption_type: str = None
    deletion_protection: bool = False
    default_stateless_actions: list = []
