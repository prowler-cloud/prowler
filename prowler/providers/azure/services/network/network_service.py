from dataclasses import dataclass

from azure.mgmt.network import NetworkManagementClient

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


########################## SQLServer
class Network(AzureService):
    def __init__(self, audit_info):
        super().__init__(NetworkManagementClient, audit_info)
        self.security_groups = self.__get_security_groups__(audit_info)
        self.bastion_hosts = self.__get_bastion_hosts__()
        self.network_watchers = self.__get_network_watchers__()

    def __get_security_groups__(self, audit_info):
        logger.info("Network - Getting Network Security Groups...")
        security_groups = {}
        for subscription, client in self.clients.items():
            try:
                security_groups.update({subscription: []})
                security_groups_list = client.network_security_groups.list_all()
                for security_group in security_groups_list:
                    subscription_id = security_group.id.split("/")[2]
                    subscription_locations = audit_info.locations[subscription_id]
                    security_groups[subscription].append(
                        SecurityGroup(
                            id=security_group.id,
                            name=security_group.name,
                            location=security_group.location,
                            security_rules=security_group.security_rules,
                            subscription_locations=subscription_locations,
                        )
                    )

            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return security_groups

    def __get_network_watchers__(self):
        logger.info("Network - Getting Network Watchers...")
        network_watchers = {}
        for subscription, client in self.clients.items():
            try:
                network_watchers.update({subscription: []})
                network_watchers_list = client.network_watchers.list_all()
                for network_watcher in network_watchers_list:
                    flow_logs = self.__get_flow_logs__(
                        subscription, network_watcher.name
                    )
                    network_watchers[subscription].append(
                        NetworkWatcher(
                            id=network_watcher.id,
                            name=network_watcher.name,
                            location=network_watcher.location,
                            flow_logs=flow_logs,
                        )
                    )

            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return network_watchers

    def __get_flow_logs__(self, subscription, network_watcher_name):
        logger.info("Network - Getting Flow Logs...")
        client = self.clients[subscription]
        resource_group = "NetworkWatcherRG"
        flow_logs = client.flow_logs.list(resource_group, network_watcher_name)
        return flow_logs

    def __get_bastion_hosts__(self):
        logger.info("Network - Getting Bastion Hosts...")
        bastion_hosts = {}
        for subscription, client in self.clients.items():
            try:
                bastion_hosts.update({subscription: []})
                bastion_hosts_list = client.bastion_hosts.list()
                for bastion_host in bastion_hosts_list:
                    bastion_hosts[subscription].append(
                        BastionHost(
                            id=bastion_host.id,
                            name=bastion_host.name,
                            location=bastion_host.location,
                        )
                    )

            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return bastion_hosts


@dataclass
class BastionHost:
    id: str
    name: str
    location: str


@dataclass
class NetworkWatcher:
    id: str
    name: str
    location: str
    flow_logs: list


@dataclass
class SecurityGroup:
    id: str
    name: str
    location: str
    security_rules: list
    subscription_locations: list
