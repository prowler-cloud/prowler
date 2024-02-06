from dataclasses import dataclass

from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.sql.models import (
    EncryptionProtector,
    FirewallRule,
    ServerBlobAuditingPolicy,
    ServerExternalAdministrator,
    ServerSecurityAlertPolicy,
    ServerVulnerabilityAssessment,
    TransparentDataEncryption,
)

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


########################## SQLServer
class SQLServer(AzureService):
    def __init__(self, audit_info):
        super().__init__(SqlManagementClient, audit_info)
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
                    encryption_protector = self.__get_enctyption_protectors__(
                        subscription, resource_group, sql_server.name
                    )
                    vulnerability_assessment = self.__get_vulnerability_assesments__(
                        subscription, resource_group, sql_server.name
                    )
                    security_alert_policies = client.server_security_alert_policies.get(
                        resource_group_name=resource_group,
                        server_name=sql_server.name,
                        security_alert_policy_name="default",
                    )
                    sql_servers[subscription].append(
                        Server(
                            id=sql_server.id,
                            name=sql_server.name,
                            public_network_access=sql_server.public_network_access,
                            minimal_tls_version=sql_server.minimal_tls_version,
                            administrators=sql_server.administrators,
                            auditing_policies=auditing_policies,
                            firewall_rules=firewall_rules,
                            encryption_protector=encryption_protector,
                            databases=self.__get_databases__(
                                subscription, resource_group, sql_server.name
                            ),
                            vulnerability_assessment=vulnerability_assessment,
                            security_alert_policies=security_alert_policies,
                        )
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return sql_servers

    def __get_resource_group__(self, id):
        resource_group = id.split("/")[4]
        return resource_group

    def __get_transparent_data_encryption__(
        self, subscription, resource_group, server_name, database_name
    ):
        client = self.clients[subscription]
        tde_encrypted = client.transparent_data_encryptions.get(
            resource_group_name=resource_group,
            server_name=server_name,
            database_name=database_name,
            transparent_data_encryption_name="current",
        )
        return tde_encrypted

    def __get_enctyption_protectors__(self, subscription, resource_group, server_name):
        client = self.clients[subscription]
        encryption_protectors = client.encryption_protectors.get(
            resource_group_name=resource_group,
            server_name=server_name,
            encryption_protector_name="current",
        )
        return encryption_protectors

    def __get_databases__(self, subscription, resource_group, server_name):
        logger.info("SQL Server - Getting server databases...")
        databases = []
        try:
            client = self.clients[subscription]
            databases_server = client.databases.list_by_server(
                resource_group_name=resource_group,
                server_name=server_name,
            )
            for database in databases_server:
                tde_encrypted = self.__get_transparent_data_encryption__(
                    subscription, resource_group, server_name, database.name
                )
                databases.append(
                    Database(
                        id=database.id,
                        name=database.name,
                        type=database.type,
                        location=database.location,
                        managed_by=database.managed_by,
                        tde_encryption=tde_encrypted,
                    )
                )
        except Exception as error:
            logger.error(
                f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return databases

    def __get_vulnerability_assesments__(
        self, subscription, resource_group, server_name
    ):
        client = self.clients[subscription]
        vulnerability_assessment = client.server_vulnerability_assessments.get(
            resource_group_name=resource_group,
            server_name=server_name,
            vulnerability_assessment_name="default",
        )
        return vulnerability_assessment


@dataclass
class Database:
    id: str
    name: str
    type: str
    location: str
    managed_by: str
    tde_encryption: TransparentDataEncryption


@dataclass
class Server:
    id: str
    name: str
    public_network_access: str
    minimal_tls_version: str
    administrators: ServerExternalAdministrator
    auditing_policies: ServerBlobAuditingPolicy
    firewall_rules: FirewallRule
    encryption_protector: EncryptionProtector = None
    databases: list[Database] = None
    vulnerability_assessment: ServerVulnerabilityAssessment = None
    security_alert_policies: ServerSecurityAlertPolicy = None
