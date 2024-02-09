from dataclasses import dataclass

from azure.mgmt.rdbms.postgresql import PostgreSQLManagementClient

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


class PostgreSQL(AzureService):
    def __init__(self, audit_info):
        super().__init__(PostgreSQLManagementClient, audit_info)
        self.postgresql_servers = self.__get_postgresql_servers__()

    def __get_postgresql_servers__(self):
        logger.info("PostgreSQL - Getting PostgreSQL servers...")
        postgresql_servers = {}
        for subscription, client in self.clients.items():
            try:
                postgresql_servers.update({subscription: []})
                postgresql_servers_list = client.servers.list()
                print("Entra aqui")
                print(postgresql_servers_list.__dict__)
                for postgresql_server in postgresql_servers_list:
                    print("Entra aqui 2")
                    print(postgresql_server)
                    resource_group = self.__get_resource_group__(postgresql_server.id)
                    postgresql_servers[subscription].append(
                        Server(
                            id=postgresql_server.id,
                            name=postgresql_server.name,
                            resource_group=resource_group,
                        )
                    )
            except Exception as e:
                logger.error(f"PostgreSQL - Error getting PostgreSQL servers: {e}")

    def __get_resource_group__(self, id):
        resource_group = id.split("/")[4]
        return resource_group


@dataclass
class Server:
    id: str
    name: str
    resource_group: str
    ssl_enforcement: str
