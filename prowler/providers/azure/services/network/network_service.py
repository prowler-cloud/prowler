import re
from dataclasses import dataclass
from typing import List, Optional

from azure.core.exceptions import ResourceNotFoundError
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
                            security_rules=[
                                SecurityRule(
                                    id=rule.id,
                                    name=rule.name,
                                    destination_port_range=getattr(
                                        rule, "destination_port_range", ""
                                    ),
                                    protocol=getattr(rule, "protocol", ""),
                                    source_address_prefix=getattr(
                                        rule, "source_address_prefix", ""
                                    ),
                                    access=getattr(rule, "access", "Allow"),
                                    direction=getattr(rule, "direction", "Inbound"),
                                )
                                for rule in getattr(
                                    security_group, "security_rules", []
                                )
                            ],
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
                    flow_logs = self._get_flow_logs(
                        subscription, network_watcher.name, network_watcher.id
                    )
                    network_watchers[subscription].append(
                        NetworkWatcher(
                            id=network_watcher.id,
                            name=network_watcher.name,
                            location=network_watcher.location,
                            flow_logs=[
                                FlowLog(
                                    id=flow_log.id,
                                    name=flow_log.name,
                                    enabled=getattr(
                                        getattr(flow_log, "properties", None),
                                        "enabled",
                                        False,
                                    ),
                                    retention_policy=getattr(
                                        getattr(flow_log, "properties", None),
                                        "retentionPolicy",
                                        None,
                                    ),
                                )
                                for flow_log in flow_logs
                            ],
                        )
                    )

            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return network_watchers

    def _get_flow_logs(self, subscription, network_watcher_name, network_watcher_id):
        logger.info("Network - Getting Flow Logs...")
        client = self.clients[subscription]
        match = re.search(r"/resourceGroups/(?P<rg>[^/]+)/", network_watcher_id)
        if not match:
            logger.error(
                f"Could not extract resource group from ID: {network_watcher_id}"
            )
            return []
        resource_group = match.group("rg")
        try:
            flow_logs = client.flow_logs.list(resource_group, network_watcher_name)
            return flow_logs
        except ResourceNotFoundError as error:
            logger.warning(
                f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return []
        except Exception as error:
            logger.error(
                f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return []

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
class RetentionPolicy:
    enabled: bool = False
    days: int = 0


@dataclass
class FlowLog:
    id: str
    name: str
    enabled: bool
    retention_policy: RetentionPolicy


@dataclass
class NetworkWatcher:
    id: str
    name: str
    location: str
    flow_logs: List[FlowLog]


@dataclass
class SecurityRule:
    id: str
    name: str
    destination_port_range: Optional[str]
    protocol: Optional[str]
    source_address_prefix: Optional[str]
    access: Optional[str]
    direction: Optional[str]


@dataclass
class SecurityGroup:
    id: str
    name: str
    location: str
    security_rules: List[SecurityRule]


@dataclass
class PublicIp:
    id: str
    name: str
    location: str
    ip_address: str
