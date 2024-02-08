from dataclasses import dataclass

from azure.mgmt.rdbms.mysql import MySQLManagementClient

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


########################## SQLServer
class MySQL(AzureService):
    def __init__(self, audit_info):
        super().__init__(MySQLManagementClient, audit_info)

        self.servers = self.__get_servers__()

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
                                ssl_enforcement=server.ssl_enforcement,
                                minimal_tls_version=server.minimal_tls_version,
                            )
                        }
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return servers


@dataclass
class Server:
    resource_id: str
    location: str
    version: str
    ssl_enforcement: str
    minimal_tls_version: str
