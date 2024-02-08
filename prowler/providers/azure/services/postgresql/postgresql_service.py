from dataclasses import dataclass

from azure.mgmt.rdbms import PostgreSQLManagementClient

from prowler.providers.azure.lib.service.service import AzureService


class PostgreSQL(AzureService):
    def __init__(self, audit_info):
        super().__init__(PostgreSQLManagementClient, audit_info)
        self.postgresql_servers = self.__get_postgresql_servers__()


@dataclass
class PostgreSQL:
    id: str
    name: str
