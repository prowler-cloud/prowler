from unittest.mock import patch

from prowler.providers.azure.services.postgresql.postgresql_service import (
    Firewall,
    PostgreSQL,
    Server,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


def mock_sqlserver_get_postgresql_flexible_servers(_):
    firewall = Firewall(
        id="id",
        name="name",
        start_ip="start_ip",
        end_ip="end_ip",
    )
    return {
        AZURE_SUBSCRIPTION_ID: [
            Server(
                id="id",
                name="name",
                resource_group="resource_group",
                require_secure_transport="ON",
                log_checkpoints="ON",
                log_connections="ON",
                log_disconnections="ON",
                connection_throttling="ON",
                log_retention_days="3",
                firewall=[firewall],
                location="location",
            )
        ]
    }


@patch(
    "prowler.providers.azure.services.postgresql.postgresql_service.PostgreSQL._get_flexible_servers",
    new=mock_sqlserver_get_postgresql_flexible_servers,
)
class Test_SqlServer_Service:
    def test_get_client(self):
        postgresql = PostgreSQL(set_mocked_azure_provider())
        assert (
            postgresql.clients[AZURE_SUBSCRIPTION_ID].__class__.__name__
            == "PostgreSQLManagementClient"
        )

    def test_get_sql_servers(self):
        postgesql = PostgreSQL(set_mocked_azure_provider())
        assert (
            postgesql.flexible_servers[AZURE_SUBSCRIPTION_ID][0].__class__.__name__
            == "Server"
        )
        assert postgesql.flexible_servers[AZURE_SUBSCRIPTION_ID][0].id == "id"
        assert postgesql.flexible_servers[AZURE_SUBSCRIPTION_ID][0].name == "name"
        assert (
            postgesql.flexible_servers[AZURE_SUBSCRIPTION_ID][0].location == "location"
        )
        assert (
            postgesql.flexible_servers[AZURE_SUBSCRIPTION_ID][0].resource_group
            == "resource_group"
        )

    def test_get_resource_group(self):
        id = "/subscriptions/subscription/resourceGroups/resource_group/providers/Microsoft.DBforPostgreSQL/flexibleServers/server"
        postgresql = PostgreSQL(set_mocked_azure_provider())
        assert postgresql._get_resource_group(id) == "resource_group"

    def test_get_require_secure_transport(self):
        postgesql = PostgreSQL(set_mocked_azure_provider())
        assert (
            postgesql.flexible_servers[AZURE_SUBSCRIPTION_ID][
                0
            ].require_secure_transport
            == "ON"
        )

    def test_get_log_checkpoints(self):
        postgesql = PostgreSQL(set_mocked_azure_provider())
        assert (
            postgesql.flexible_servers[AZURE_SUBSCRIPTION_ID][0].log_checkpoints == "ON"
        )

    def test_get_log_connections(self):
        postgesql = PostgreSQL(set_mocked_azure_provider())
        assert (
            postgesql.flexible_servers[AZURE_SUBSCRIPTION_ID][0].log_connections == "ON"
        )

    def test_get_log_disconnections(self):
        postgesql = PostgreSQL(set_mocked_azure_provider())
        assert (
            postgesql.flexible_servers[AZURE_SUBSCRIPTION_ID][0].log_disconnections
            == "ON"
        )

    def test_get_connection_throttling(self):
        postgesql = PostgreSQL(set_mocked_azure_provider())
        assert (
            postgesql.flexible_servers[AZURE_SUBSCRIPTION_ID][0].connection_throttling
            == "ON"
        )

    def test_get_log_retention_days(self):
        postgesql = PostgreSQL(set_mocked_azure_provider())
        assert (
            postgesql.flexible_servers[AZURE_SUBSCRIPTION_ID][0].log_retention_days
            == "3"
        )

    def test_get_firewall(self):
        postgesql = PostgreSQL(set_mocked_azure_provider())
        assert (
            postgesql.flexible_servers[AZURE_SUBSCRIPTION_ID][0]
            .firewall[0]
            .__class__.__name__
            == "Firewall"
        )
        assert (
            postgesql.flexible_servers[AZURE_SUBSCRIPTION_ID][0].firewall[0].id == "id"
        )
        assert (
            postgesql.flexible_servers[AZURE_SUBSCRIPTION_ID][0].firewall[0].name
            == "name"
        )
        assert (
            postgesql.flexible_servers[AZURE_SUBSCRIPTION_ID][0].firewall[0].start_ip
            == "start_ip"
        )
        assert (
            postgesql.flexible_servers[AZURE_SUBSCRIPTION_ID][0].firewall[0].end_ip
            == "end_ip"
        )
