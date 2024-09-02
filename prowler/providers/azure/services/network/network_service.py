from dataclasses import dataclass

from azure.mgmt.network import NetworkManagementClient

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService


class Network(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(NetworkManagementClient, provider)
        self.security_groups = self._get_security_groups()
        self.bastion_hosts = self._get_bastion_hosts()
        self.network_watchers = self._get_network_watchers()
        self.public_ip_addresses = self._get_public_ip_addresses()

    def _get_security_groups(self):
        logger.info("Network - Getting Network Security Groups...")
        security_groups = {}
        for subscription, client in self.clients.items():
            try:
                security_groups.update({subscription: []})
                security_groups_list = client.network_security_groups.list_all()
                for security_group in security_groups_list:
                    security_groups[subscription].append(
                        SecurityGroup(
                            id=security_group.id,
                            name=security_group.name,
                            location=security_group.location,
                            security_rules=security_group.security_rules,
                        )
                    )

            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return security_groups

    def _get_network_watchers(self):
        logger.info("Network - Getting Network Watchers...")
        network_watchers = {}
        for subscription, client in self.clients.items():
            try:
                network_watchers.update({subscription: []})
                network_watchers_list = client.network_watchers.list_all()
                for network_watcher in network_watchers_list:
                    flow_logs = self._get_flow_logs(subscription, network_watcher.name)
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

    def _get_flow_logs(self, subscription, network_watcher_name):
        logger.info("Network - Getting Flow Logs...")
        client = self.clients[subscription]
        resource_group = "NetworkWatcherRG"
        flow_logs = client.flow_logs.list(resource_group, network_watcher_name)
        return flow_logs

    def _get_bastion_hosts(self):
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

    def _get_public_ip_addresses(self):
        logger.info("Network - Getting Public IP Addresses...")
        public_ip_addresses = {}
        for subscription, client in self.clients.items():
            try:
                public_ip_addresses.update({subscription: []})
                public_ip_addresses_list = client.public_ip_addresses.list_all()
                for public_ip_address in public_ip_addresses_list:
                    public_ip_addresses[subscription].append(
                        PublicIp(
                            id=public_ip_address.id,
                            name=public_ip_address.name,
                            location=public_ip_address.location,
                            ip_address=public_ip_address.ip_address,
                        )
                    )

            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return public_ip_addresses


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


@dataclass
class PublicIp:
    id: str
    name: str
    location: str
    ip_address: str
