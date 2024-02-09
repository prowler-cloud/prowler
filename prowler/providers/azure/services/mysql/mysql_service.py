from dataclasses import dataclass

from azure.mgmt.rdbms.mysql_flexibleservers import MySQLManagementClient

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


########################## SQLServer
class MySQL(AzureService):
    def __init__(self, audit_info):
        super().__init__(MySQLManagementClient, audit_info)

        self.servers = self.__get_servers__()
        self.configurations = self.__get_configurations__()

    def __get_servers__(self):
        logger.info("MySQL - Getting servers...")
        servers = {}
        for subscription_name, client in self.clients.items():
            try:
                servers_list = client.servers.list()
                servers.update({subscription_name: {}})
                for server in servers_list:
                    servers[subscription_name].update(
                        {
                            server.name: Server(
                                resource_id=server.id,
                                location=server.location,
                                version=server.version,
                                resource_group=server.id.split("/")[4],
                            )
                        }
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return servers

    def __get_configurations__(self):
        logger.info("MySQL - Getting configurations...")
        configurations = {}
        for subscription_name, client in self.clients.items():
            for server_name, server in self.servers[subscription_name].items():
                try:
                    configurations_list = client.configurations.list_by_server(
                        resource_group_name=server.resource_group,
                        server_name=server_name,
                    )
                    configurations.update({subscription_name: {}})
                    for configuration in configurations_list:
                        configurations[subscription_name].update(
                            {
                                configuration.name: Configuration(
                                    resource_id=configuration.id,
                                    server_name=server_name,
                                    description=configuration.description,
                                    value=configuration.value,
                                )
                            }
                        )
                except Exception as error:
                    logger.error(
                        f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        return configurations


@dataclass
class Server:
    resource_id: str
    location: str
    version: str
    resource_group: str


@dataclass
class Configuration:
    resource_id: str
    server_name: str
    description: str
    value: str
