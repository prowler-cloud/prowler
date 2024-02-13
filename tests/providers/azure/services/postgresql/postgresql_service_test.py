from unittest.mock import patch

from prowler.providers.azure.services.postgresql.postgresql_service import (
    PostgreSQL,
    Server,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_audit_info,
)


def mock_sqlserver_get_postgresql_flexible_servers(_):

    return {
        AZURE_SUBSCRIPTION: [
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
            )
        ]
    }


@patch(
    "prowler.providers.azure.services.postgresql.postgresql_service.PostgreSQL.__get_flexible_servers__",
    new=mock_sqlserver_get_postgresql_flexible_servers,
)
class Test_SqlServer_Service:
    def test__get_client__(self):
        postgresql = PostgreSQL(set_mocked_azure_audit_info())
        assert (
            postgresql.clients[AZURE_SUBSCRIPTION].__class__.__name__
            == "PostgreSQLManagementClient"
        )

    def test__get_sql_servers__(self):
        postgesql = PostgreSQL(set_mocked_azure_audit_info())
        assert (
            postgesql.flexible_servers[AZURE_SUBSCRIPTION][0].__class__.__name__
            == "Server"
        )
        assert postgesql.flexible_servers[AZURE_SUBSCRIPTION][0].id == "id"
        assert postgesql.flexible_servers[AZURE_SUBSCRIPTION][0].name == "name"
        assert (
            postgesql.flexible_servers[AZURE_SUBSCRIPTION][0].resource_group
            == "resource_group"
        )

    def test__get_resource_group__(self):
        id = "/subscriptions/subscription/resourceGroups/resource_group/providers/Microsoft.DBforPostgreSQL/flexibleServers/server"
        postgresql = PostgreSQL(set_mocked_azure_audit_info())
        assert postgresql.__get_resource_group__(id) == "resource_group"

    def test__get_require_secure_transport__(self):
        postgesql = PostgreSQL(set_mocked_azure_audit_info())
        assert (
            postgesql.flexible_servers[AZURE_SUBSCRIPTION][0].require_secure_transport
            == "ON"
        )

    def test__get_log_checkpoints__(self):
        postgesql = PostgreSQL(set_mocked_azure_audit_info())
        assert postgesql.flexible_servers[AZURE_SUBSCRIPTION][0].log_checkpoints == "ON"

    def test__get_log_connections__(self):
        postgesql = PostgreSQL(set_mocked_azure_audit_info())
        assert postgesql.flexible_servers[AZURE_SUBSCRIPTION][0].log_connections == "ON"

    def test__get_log_disconnections__(self):
        postgesql = PostgreSQL(set_mocked_azure_audit_info())
        assert (
            postgesql.flexible_servers[AZURE_SUBSCRIPTION][0].log_disconnections == "ON"
        )

    def test__get_connection_throttling__(self):
        postgesql = PostgreSQL(set_mocked_azure_audit_info())
        assert (
            postgesql.flexible_servers[AZURE_SUBSCRIPTION][0].connection_throttling
            == "ON"
        )

    def test__get_log_retention_days__(self):
        postgesql = PostgreSQL(set_mocked_azure_audit_info())
        assert (
            postgesql.flexible_servers[AZURE_SUBSCRIPTION][0].log_retention_days == "3"
        )
