from dataclasses import dataclass

from azure.mgmt.rdbms.postgresql_flexibleservers import PostgreSQLManagementClient

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService


class PostgreSQL(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(PostgreSQLManagementClient, provider)
        self.flexible_servers = self.__get_flexible_servers__()

    def __get_flexible_servers__(self):
        logger.info("PostgreSQL - Getting PostgreSQL servers...")
        flexible_servers = {}
        for subscription, client in self.clients.items():
            try:
                flexible_servers.update({subscription: []})
                flexible_servers_list = client.servers.list()
                for postgresql_server in flexible_servers_list:
                    resource_group = self.__get_resource_group__(postgresql_server.id)
                    require_secure_transport = self.__get_require_secure_transport__(
                        subscription, resource_group, postgresql_server.name
                    )
                    log_checkpoints = self.__get_log_checkpoints__(
                        subscription, resource_group, postgresql_server.name
                    )
                    log_disconnections = self.__get_log_disconnections__(
                        subscription, resource_group, postgresql_server.name
                    )
                    log_connections = self.__get_log_connections__(
                        subscription, resource_group, postgresql_server.name
                    )
                    connection_throttling = self.__get_connection_throttling__(
                        subscription, resource_group, postgresql_server.name
                    )
                    log_retention_days = self.__get_log_retention_days__(
                        subscription, resource_group, postgresql_server.name
                    )
                    firewall = self.__get_firewall__(
                        subscription, resource_group, postgresql_server.name
                    )
                    location = self.__get_location__(
                        subscription, resource_group, postgresql_server.name
                    )
                    flexible_servers[subscription].append(
                        Server(
                            id=postgresql_server.id,
                            name=postgresql_server.name,
                            resource_group=resource_group,
                            require_secure_transport=require_secure_transport,
                            log_checkpoints=log_checkpoints,
                            log_connections=log_connections,
                            log_disconnections=log_disconnections,
                            connection_throttling=connection_throttling,
                            log_retention_days=log_retention_days,
                            firewall=firewall,
                            location=location,
                        )
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return flexible_servers

    def __get_resource_group__(self, id):
        resource_group = id.split("/")[4]
        return resource_group

    def __get_require_secure_transport__(
        self, subscription, resouce_group_name, server_name
    ):
        client = self.clients[subscription]
        require_secure_transport = client.configurations.get(
            resouce_group_name, server_name, "require_secure_transport"
        )
        return require_secure_transport.value.upper()

    def __get_log_checkpoints__(self, subscription, resouce_group_name, server_name):
        client = self.clients[subscription]
        log_checkpoints = client.configurations.get(
            resouce_group_name, server_name, "log_checkpoints"
        )
        return log_checkpoints.value.upper()

    def __get_log_connections__(self, subscription, resouce_group_name, server_name):
        client = self.clients[subscription]
        log_connections = client.configurations.get(
            resouce_group_name, server_name, "log_connections"
        )
        return log_connections.value.upper()

    def __get_log_disconnections__(self, subscription, resouce_group_name, server_name):
        client = self.clients[subscription]
        log_disconnections = client.configurations.get(
            resouce_group_name, server_name, "log_disconnections"
        )
        return log_disconnections.value.upper()

    def __get_location__(self, subscription, resouce_group_name, server_name):
        client = self.clients[subscription]
        location = client.servers.get(resouce_group_name, server_name).location
        return location

    def __get_connection_throttling__(
        self, subscription, resouce_group_name, server_name
    ):
        client = self.clients[subscription]
        connection_throttling = client.configurations.get(
            resouce_group_name, server_name, "connection_throttle.enable"
        )
        return connection_throttling.value.upper()

    def __get_log_retention_days__(self, subscription, resouce_group_name, server_name):
        client = self.clients[subscription]
        try:
            log_retention_days = client.configurations.get(
                resouce_group_name, server_name, "log_retention_days"
            )
            log_retention_days = log_retention_days.value
        except Exception:
            log_retention_days = None
        return log_retention_days

    def __get_firewall__(self, subscription, resource_group, server_name):
        client = self.clients[subscription]
        firewall = client.firewall_rules.list_by_server(resource_group, server_name)
        firewall_list = []
        for rule in firewall:
            firewall_list.append(
                Firewall(
                    id=rule.id,
                    name=rule.name,
                    start_ip=rule.start_ip_address,
                    end_ip=rule.end_ip_address,
                )
            )
        return firewall_list


@dataclass
class Firewall:
    id: str
    name: str
    start_ip: str
    end_ip: str


@dataclass
class Server:
    id: str
    name: str
    resource_group: str
    require_secure_transport: str
    log_checkpoints: str
    log_connections: str
    log_disconnections: str
    connection_throttling: str
    log_retention_days: str
    firewall: list[Firewall]
    location: str
