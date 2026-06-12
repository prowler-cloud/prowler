from unittest.mock import MagicMock, patch

from prowler.providers.azure.services.postgresql.postgresql_service import (
    EntraIdAdmin,
    Firewall,
    PostgreSQL,
    Server,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    RESOURCE_GROUP,
    RESOURCE_GROUP_LIST,
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
                location="location",
                require_secure_transport="ON",
                active_directory_auth="ENABLED",
                entra_id_admins=[
                    EntraIdAdmin(
                        object_id="11111111-1111-1111-1111-111111111111",
                        principal_name="Test Admin User",
                        principal_type="User",
                        tenant_id="22222222-2222-2222-2222-222222222222",
                    )
                ],
                log_checkpoints="ON",
                log_connections="ON",
                log_disconnections="ON",
                connection_throttling="ON",
                log_retention_days="3",
                firewall=[firewall],
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

    def test_get_active_directory_auth(self):
        postgresql = PostgreSQL(set_mocked_azure_provider())
        assert (
            postgresql.flexible_servers[AZURE_SUBSCRIPTION_ID][0].active_directory_auth
            == "ENABLED"
        )

    def test_get_entra_id_admins(self):
        postgresql = PostgreSQL(set_mocked_azure_provider())
        admins = postgresql.flexible_servers[AZURE_SUBSCRIPTION_ID][0].entra_id_admins
        assert isinstance(admins, list)
        assert len(admins) == 1
        assert isinstance(admins[0], EntraIdAdmin)
        assert admins[0].principal_name == "Test Admin User"
        assert admins[0].object_id == "11111111-1111-1111-1111-111111111111"

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


class Test_PostgreSQL_get_flexible_servers:
    def test_get_flexible_servers_no_resource_groups(self):
        mock_client = MagicMock()
        mock_client.servers.list.return_value = []

        with patch(
            "prowler.providers.azure.services.postgresql.postgresql_service.PostgreSQL._get_flexible_servers",
            return_value={},
        ):
            postgresql = PostgreSQL(set_mocked_azure_provider())

        postgresql.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        postgresql.resource_groups = None

        result = postgresql._get_flexible_servers()

        mock_client.servers.list.assert_called_once()
        mock_client.servers.list_by_resource_group.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_flexible_servers_with_resource_group(self):
        mock_client = MagicMock()
        mock_client.servers.list_by_resource_group.return_value = []

        with patch(
            "prowler.providers.azure.services.postgresql.postgresql_service.PostgreSQL._get_flexible_servers",
            return_value={},
        ):
            postgresql = PostgreSQL(set_mocked_azure_provider())

        postgresql.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        postgresql.resource_groups = {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}

        result = postgresql._get_flexible_servers()

        mock_client.servers.list_by_resource_group.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP
        )
        mock_client.servers.list.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_flexible_servers_empty_resource_group_for_subscription(self):
        mock_client = MagicMock()

        with patch(
            "prowler.providers.azure.services.postgresql.postgresql_service.PostgreSQL._get_flexible_servers",
            return_value={},
        ):
            postgresql = PostgreSQL(set_mocked_azure_provider())

        postgresql.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        postgresql.resource_groups = {AZURE_SUBSCRIPTION_ID: []}

        result = postgresql._get_flexible_servers()

        mock_client.servers.list_by_resource_group.assert_not_called()
        mock_client.servers.list.assert_not_called()
        assert result[AZURE_SUBSCRIPTION_ID] == []

    def test_get_flexible_servers_with_multiple_resource_groups(self):
        mock_client = MagicMock()
        mock_client.servers.list_by_resource_group.return_value = []

        with patch(
            "prowler.providers.azure.services.postgresql.postgresql_service.PostgreSQL._get_flexible_servers",
            return_value={},
        ):
            postgresql = PostgreSQL(set_mocked_azure_provider())

        postgresql.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        postgresql.resource_groups = {AZURE_SUBSCRIPTION_ID: RESOURCE_GROUP_LIST}

        result = postgresql._get_flexible_servers()

        assert mock_client.servers.list_by_resource_group.call_count == 2
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_flexible_servers_with_mixed_case_resource_group(self):
        mock_client = MagicMock()
        mock_client.servers.list_by_resource_group.return_value = []

        with patch(
            "prowler.providers.azure.services.postgresql.postgresql_service.PostgreSQL._get_flexible_servers",
            return_value={},
        ):
            postgresql = PostgreSQL(set_mocked_azure_provider())

        postgresql.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        postgresql.resource_groups = {AZURE_SUBSCRIPTION_ID: ["RG"]}

        postgresql._get_flexible_servers()

        mock_client.servers.list_by_resource_group.assert_called_once_with(
            resource_group_name="RG"
        )
