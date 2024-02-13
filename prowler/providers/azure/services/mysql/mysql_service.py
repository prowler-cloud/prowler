from dataclasses import dataclass

from azure.mgmt.rdbms.mysql_flexibleservers import MySQLManagementClient

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


########################## MySQL
class MySQL(AzureService):
    def __init__(self, audit_info):
        super().__init__(MySQLManagementClient, audit_info)

        self.flexible_servers = self.__get_flexible_servers__()

    def __get_flexible_servers__(self):
        logger.info("MySQL - Getting servers...")
        servers = {}
        for subscription_name, client in self.clients.items():
            try:
                servers_list = client.servers.list()
                servers.update({subscription_name: {}})
                for server in servers_list:
                    servers[subscription_name].update(
                        {
                            server.name: FlexibleServer(
                                resource_id=server.id,
                                location=server.location,
                                version=server.version,
                                configurations=self.__get_configurations__(
                                    client, server.id.split("/")[4], server.name
                                ),
                            )
                        }
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return servers

    def __get_configurations__(self, client, resource_group, server_name):
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
class FlexibleServer:
    resource_id: str
    location: str
    version: str
    configurations: dict


@dataclass
class Configuration:
    resource_id: str
    description: str
    value: str
