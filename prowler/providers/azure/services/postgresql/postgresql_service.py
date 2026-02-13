from dataclasses import dataclass

from azure.mgmt.postgresqlflexibleservers import PostgreSQLManagementClient

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService


class PostgreSQL(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(PostgreSQLManagementClient, provider)
        self.flexible_servers = self._get_flexible_servers()

    def _get_flexible_servers(self):
        logger.info("PostgreSQL - Getting PostgreSQL servers...")
        flexible_servers = {}
        for subscription, client in self.clients.items():
            try:
                flexible_servers.update({subscription: []})
                flexible_servers_list = client.servers.list()
                for postgresql_server in flexible_servers_list:
                    resource_group = self._get_resource_group(postgresql_server.id)
                    # Fetch full server object once to extract multiple properties
                    server_details = client.servers.get(
                        resource_group, postgresql_server.name
                    )
                    require_secure_transport = self._get_require_secure_transport(
                        subscription, resource_group, postgresql_server.name
                    )
                    active_directory_auth = self._extract_active_directory_auth(
                        server_details
                    )
                    entra_id_admins = self._get_entra_id_admins(
                        subscription, resource_group, postgresql_server.name
                    )
                    log_checkpoints = self._get_log_checkpoints(
                        subscription, resource_group, postgresql_server.name
                    )
                    log_disconnections = self._get_log_disconnections(
                        subscription, resource_group, postgresql_server.name
                    )
                    log_connections = self._get_log_connections(
                        subscription, resource_group, postgresql_server.name
                    )
                    connection_throttling = self._get_connection_throttling(
                        subscription, resource_group, postgresql_server.name
                    )
                    log_retention_days = self._get_log_retention_days(
                        subscription, resource_group, postgresql_server.name
                    )
                    firewall = self._get_firewall(
                        subscription, resource_group, postgresql_server.name
                    )
                    location = server_details.location
                    flexible_servers[subscription].append(
                        Server(
                            id=postgresql_server.id,
                            name=postgresql_server.name,
                            resource_group=resource_group,
                            location=location,
                            require_secure_transport=require_secure_transport,
                            active_directory_auth=active_directory_auth,
                            entra_id_admins=entra_id_admins,
                            log_checkpoints=log_checkpoints,
                            log_connections=log_connections,
                            log_disconnections=log_disconnections,
                            connection_throttling=connection_throttling,
                            log_retention_days=log_retention_days,
                            firewall=firewall,
                        )
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return flexible_servers

    def _get_resource_group(self, id):
        resource_group = id.split("/")[4]
        return resource_group

    def _get_require_secure_transport(
        self, subscription, resouce_group_name, server_name
    ):
        client = self.clients[subscription]
        require_secure_transport = client.configurations.get(
            resouce_group_name, server_name, "require_secure_transport"
        )
        return require_secure_transport.value.upper()

    def _get_log_checkpoints(self, subscription, resouce_group_name, server_name):
        client = self.clients[subscription]
        log_checkpoints = client.configurations.get(
            resouce_group_name, server_name, "log_checkpoints"
        )
        return log_checkpoints.value.upper()

    def _get_log_connections(self, subscription, resouce_group_name, server_name):
        client = self.clients[subscription]
        log_connections = client.configurations.get(
            resouce_group_name, server_name, "log_connections"
        )
        return log_connections.value.upper()

    def _get_log_disconnections(self, subscription, resouce_group_name, server_name):
        client = self.clients[subscription]
        log_disconnections = client.configurations.get(
            resouce_group_name, server_name, "log_disconnections"
        )
        return log_disconnections.value.upper()

    def _extract_active_directory_auth(self, server):
        """Extract active directory auth from a server object (no API call)."""
        try:
            auth_config = getattr(server, "auth_config", None)
            active_directory_auth = (
                getattr(auth_config, "active_directory_auth", None)
                if auth_config is not None
                else None
            )
            # Normalize enum/string to upper string
            if hasattr(active_directory_auth, "value"):
                return str(active_directory_auth.value).upper()
            return (
                str(active_directory_auth).upper()
                if active_directory_auth is not None
                else None
            )
        except Exception as e:
            logger.error(f"Error extracting active directory auth: {e}")
            return None

    def _get_entra_id_admins(self, subscription, resource_group_name, server_name):
        client = self.clients[subscription]
        try:
            admins = client.administrators.list_by_server(
                resource_group_name, server_name
            )
            admin_list = []
            for admin in admins:
                admin_list.append(
                    EntraIdAdmin(
                        object_id=admin.object_id,
                        principal_name=admin.principal_name,
                        principal_type=admin.principal_type,
                        tenant_id=admin.tenant_id,
                    )
                )
            return admin_list
        except Exception as e:
            logger.error(f"Error getting Entra ID admins for {server_name}: {e}")
            return []

    def _get_connection_throttling(self, subscription, resouce_group_name, server_name):
        client = self.clients[subscription]
        connection_throttling = client.configurations.get(
            resouce_group_name, server_name, "connection_throttle.enable"
        )
        return connection_throttling.value.upper()

    def _get_log_retention_days(self, subscription, resouce_group_name, server_name):
        client = self.clients[subscription]
        try:
            log_retention_days = client.configurations.get(
                resouce_group_name, server_name, "log_retention_days"
            )
            log_retention_days = log_retention_days.value
        except Exception:
            log_retention_days = None
        return log_retention_days

    def _get_firewall(self, subscription, resource_group, server_name):
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
class EntraIdAdmin:
    object_id: str
    principal_name: str
    principal_type: str
    tenant_id: str


@dataclass
class Server:
    id: str
    name: str
    resource_group: str
    location: str
    require_secure_transport: str
    active_directory_auth: str
    entra_id_admins: list[EntraIdAdmin]
    log_checkpoints: str
    log_connections: str
    log_disconnections: str
    connection_throttling: str
    log_retention_days: str
    firewall: list[Firewall]
