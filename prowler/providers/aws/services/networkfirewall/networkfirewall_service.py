import threading

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWS_Service


################## NetworkFirewall
class NetworkFirewall(AWS_Service):
    def __init__(self, audit_info):
        # Call AWS_Service's __init__
        super().__init__("network-firewall", audit_info)
        self.network_firewalls = []
        self.__threading_call__(self.__list_firewalls__)
        self.__describe_firewall__()

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

    def __list_firewalls__(self, regional_client):
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
                        self.network_firewalls.append(
                            Firewall(
                                arn=network_firewall.get("FirewallArn"),
                                region=regional_client.region,
                                name=network_firewall.get("FirewallName"),
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_firewall__(self):
        logger.info("Network Firewall - Describe Network Firewalls...")
        try:
            for network_firewall in self.network_firewalls:
                regional_client = self.regional_clients[network_firewall.region]
                describe_firewall = regional_client.describe_firewall(
                    FirewallArn=network_firewall.arn
                )["Firewall"]
                network_firewall.policy_arn = describe_firewall.get("FirewallPolicyArn")
                network_firewall.vpc_id = describe_firewall.get("VpcId")
                network_firewall.tags = describe_firewall.get("Tags")
                network_firewall.encryption_type = describe_firewall.get(
                    "EncryptionConfiguration"
                ).get("Type")
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )


class Firewall(BaseModel):
    arn: str
    name: str
    region: str
    policy_arn: str = None
    vpc_id: str = None
    tags: list = []
    encryption_type: str = None
