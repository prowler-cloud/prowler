from dataclasses import dataclass

from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.sql.models import (
    FirewallRule,
    ServerBlobAuditingPolicy,
    ServerExternalAdministrator,
)

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


########################## SQLServer
class SQLServer(AzureService):
    def __init__(self, provider):
        super().__init__(SqlManagementClient, provider)
        self.sql_servers = self.__get_sql_servers__()

    def __get_sql_servers__(self):
        logger.info("SQL Server - Getting SQL servers...")
        sql_servers = {}
        for subscription, client in self.clients.items():
            try:
                sql_servers.update({subscription: []})
                sql_servers_list = client.servers.list()
                for sql_server in sql_servers_list:
                    resource_group = self.__get_resource_group__(sql_server.id)
                    auditing_policies = (
                        client.server_blob_auditing_policies.list_by_server(
                            resource_group_name=resource_group,
                            server_name=sql_server.name,
                        )
                    )
                    firewall_rules = client.firewall_rules.list_by_server(
                        resource_group_name=resource_group, server_name=sql_server.name
                    )
                    sql_servers[subscription].append(
                        SQL_Server(
                            id=sql_server.id,
                            name=sql_server.name,
                            public_network_access=sql_server.public_network_access,
                            minimal_tls_version=sql_server.minimal_tls_version,
                            administrators=sql_server.administrators,
                            auditing_policies=auditing_policies,
                            firewall_rules=firewall_rules,
                        )
                    )
            except Exception as error:
                logger.error(f"Subscription name: {subscription}")
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return sql_servers

    def __get_resource_group__(self, id):
        resource_group = id.split("/")[4]
        return resource_group


@dataclass
class SQL_Server:
    id: str
    name: str
    public_network_access: str
    minimal_tls_version: str
    administrators: ServerExternalAdministrator
    auditing_policies: ServerBlobAuditingPolicy
    firewall_rules: FirewallRule

    def __init__(
        self,
        id,
        name,
        public_network_access,
        minimal_tls_version,
        administrators,
        auditing_policies,
        firewall_rules,
    ):
        self.id = id
        self.name = name
        self.public_network_access = public_network_access
        self.minimal_tls_version = minimal_tls_version
        self.administrators = administrators
        self.auditing_policies = auditing_policies
        self.firewall_rules = firewall_rules
