from dataclasses import dataclass
from typing import Optional

from azure.mgmt.rdbms.mysql_flexibleservers import MySQLManagementClient

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService


class MySQL(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(MySQLManagementClient, provider)

        self.flexible_servers = self._get_flexible_servers()

    def _get_flexible_servers(self):
        logger.info("MySQL - Getting servers...")
        servers = {}
        for subscription_name, client in self.clients.items():
            try:
                servers_list = client.servers.list()
                servers.update({subscription_name: {}})
                for server in servers_list:
                    backup = getattr(server, "backup", None)
                    ha = getattr(server, "high_availability", None)
                    servers[subscription_name].update(
                        {
                            server.id: FlexibleServer(
                                resource_id=server.id,
                                name=server.name,
                                location=server.location,
                                version=server.version,
                                configurations=self._get_configurations(
                                    client, server.id.split("/")[4], server.name
                                ),
                                geo_redundant_backup=getattr(
                                    backup, "geo_redundant_backup", None
                                ),
                                backup_retention_days=getattr(
                                    backup, "backup_retention_days", None
                                ),
                                high_availability_mode=getattr(
                                    ha, "mode", None
                                ),
                            )
                        }
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return servers

    def _get_configurations(self, client, resource_group, server_name):
        logger.info(f"MySQL - Getting configurations from server {server_name} ...")
        configurations = {}
        try:
            configurations_list = client.configurations.list_by_server(
                resource_group, server_name
            )
            for configuration in configurations_list:
                configurations.update(
                    {
                        configuration.name: Configuration(
                            resource_id=configuration.id,
                            description=configuration.description,
                            value=configuration.value,
                        )
                    }
                )
        except Exception as error:
            logger.error(
                f"Server name: {server_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return configurations


@dataclass
class Configuration:
    resource_id: str
    description: str
    value: str


@dataclass
class FlexibleServer:
    resource_id: str
    name: str
    location: str
    version: str
    configurations: dict[Configuration]
    geo_redundant_backup: Optional[str] = None
    backup_retention_days: Optional[int] = None
    high_availability_mode: Optional[str] = None
