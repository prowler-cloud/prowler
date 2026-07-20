from unittest.mock import MagicMock, patch

import pytest
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError

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

    def test_get_connection_throttling_missing_parameter_returns_none(self):
        # PostgreSQL v18 removed the "connection_throttle.enable" parameter; when
        # it is genuinely absent the Azure SDK raises ResourceNotFoundError, and
        # the service treats that as "not enabled" (quiet None) instead of
        # aborting the whole subscription's server inventory.
        postgresql = PostgreSQL(set_mocked_azure_provider())
        mock_client = MagicMock()
        mock_client.configurations.get.side_effect = ResourceNotFoundError(
            "The configuration 'connection_throttle.enable' does not exist for "
            "server version 18."
        )
        postgresql.clients[AZURE_SUBSCRIPTION_ID] = mock_client
        with patch(
            "prowler.providers.azure.services.postgresql.postgresql_service.logger"
        ) as mock_logger:
            result = postgresql._get_connection_throttling(
                AZURE_SUBSCRIPTION_ID, "resource_group", "server_name"
            )
        assert result is None
        mock_logger.error.assert_not_called()

    def test_get_connection_throttling_unexpected_error_propagates(self):
        # Any other failure (permissions, throttling, transient API errors) must
        # NOT be swallowed into None: that would make the downstream check report
        # the server as having throttling disabled, hiding a collection failure
        # as a security finding. The error propagates so the per-server handler
        # in _get_flexible_servers can record it as a collection failure.
        postgresql = PostgreSQL(set_mocked_azure_provider())
        mock_client = MagicMock()
        mock_client.configurations.get.side_effect = HttpResponseError(
            "(AuthorizationFailed) permission denied"
        )
        postgresql.clients[AZURE_SUBSCRIPTION_ID] = mock_client
        with pytest.raises(HttpResponseError):
            postgresql._get_connection_throttling(
                AZURE_SUBSCRIPTION_ID, "resource_group", "server_name"
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

    def test_get_entra_id_admins_aad_not_enabled_logs_warning(self):
        # A server using PostgreSQL authentication only (Entra/Azure AD auth
        # disabled) is an expected state; it should be logged as a warning, not
        # an error, and return an empty admin list.
        postgresql = PostgreSQL(set_mocked_azure_provider())
        mock_client = MagicMock()
        mock_client.administrators.list_by_server.side_effect = Exception(
            "Azure AD authentication is not enabled for the given server"
        )
        postgresql.clients[AZURE_SUBSCRIPTION_ID] = mock_client
        with patch(
            "prowler.providers.azure.services.postgresql.postgresql_service.logger"
        ) as mock_logger:
            result = postgresql._get_entra_id_admins(
                AZURE_SUBSCRIPTION_ID, "resource_group", "server_name"
            )
        assert result == []
        mock_logger.warning.assert_called_once()
        mock_logger.error.assert_not_called()

    def test_get_entra_id_admins_unexpected_error_logs_error(self):
        # Any other failure (permissions, throttling, transient API errors) is a
        # genuine problem and must still be logged as an error.
        postgresql = PostgreSQL(set_mocked_azure_provider())
        mock_client = MagicMock()
        mock_client.administrators.list_by_server.side_effect = Exception(
            "Some unexpected failure"
        )
        postgresql.clients[AZURE_SUBSCRIPTION_ID] = mock_client
        with patch(
            "prowler.providers.azure.services.postgresql.postgresql_service.logger"
        ) as mock_logger:
            result = postgresql._get_entra_id_admins(
                AZURE_SUBSCRIPTION_ID, "resource_group", "server_name"
            )
        assert result == []
        mock_logger.error.assert_called_once()
        mock_logger.warning.assert_not_called()

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


def _make_server(name):
    server = MagicMock()
    server.id = (
        f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        f"Microsoft.DBforPostgreSQL/flexibleServers/{name}"
    )
    server.name = name
    return server


class Test_PostgreSQL_Service_Resilience:
    """Collecting one flexible server must never abort collection of the rest of
    the subscription (regression: a missing/failing per-server configuration
    lookup silently dropped every remaining server)."""

    def _build_service_with_client(self, mock_client):
        # Skip the real network call during construction, then run the real
        # collection against the mocked management client.
        with patch.object(PostgreSQL, "_get_flexible_servers", return_value={}):
            postgresql = PostgreSQL(set_mocked_azure_provider())
        postgresql.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        return postgresql

    def test_missing_connection_throttle_config_still_collects_server(self):
        # The "connection_throttle.enable" parameter was removed in PostgreSQL
        # 16+, so the lookup raises ConfigurationNotExists on newer servers.
        dev = _make_server("dev")
        prd = _make_server("prd")

        mock_client = MagicMock()
        mock_client.servers.list.return_value = [dev, prd]
        server_details = MagicMock()
        server_details.location = "westeurope"
        mock_client.servers.get.return_value = server_details
        mock_client.administrators.list_by_server.return_value = []
        mock_client.firewall_rules.list_by_server.return_value = []

        def configurations_get(resource_group, server_name, key):
            if key == "connection_throttle.enable" and server_name == "prd":
                # Azure raises ResourceNotFoundError (ConfigurationNotExists)
                # when the parameter does not exist on the server.
                raise ResourceNotFoundError(
                    "(ConfigurationNotExists) The configuration "
                    "'connection_throttle.enable' does not exist for prd server "
                    "version 18."
                )
            return MagicMock(value="ON")

        mock_client.configurations.get.side_effect = configurations_get

        postgresql = self._build_service_with_client(mock_client)
        servers = postgresql._get_flexible_servers()

        names = sorted(server.name for server in servers[AZURE_SUBSCRIPTION_ID])
        assert names == ["dev", "prd"]
        prd_server = next(s for s in servers[AZURE_SUBSCRIPTION_ID] if s.name == "prd")
        assert prd_server.connection_throttling is None
        dev_server = next(s for s in servers[AZURE_SUBSCRIPTION_ID] if s.name == "dev")
        assert dev_server.connection_throttling == "ON"

    def test_log_retention_reads_flexible_server_parameter_name(self):
        # Azure Flexible Server exposes log retention under the parameter
        # "logfiles.retention_days". The legacy Single Server name
        # "log_retention_days" does not exist on Flexible Server (Azure raises
        # ConfigurationNotExists), which previously left log_retention_days=None
        # and made postgresql_flexible_server_log_retention_days_greater_3 always
        # FAIL. Regression test for #11757.
        dev = _make_server("dev")

        mock_client = MagicMock()
        mock_client.servers.list.return_value = [dev]
        server_details = MagicMock()
        server_details.location = "westeurope"
        mock_client.servers.get.return_value = server_details
        mock_client.administrators.list_by_server.return_value = []
        mock_client.firewall_rules.list_by_server.return_value = []

        def configurations_get(resource_group, server_name, key):
            if key == "log_retention_days":
                raise ResourceNotFoundError(
                    "(ConfigurationNotExists) The configuration "
                    "'log_retention_days' does not exist for dev server "
                    "version 18."
                )
            if key == "logfiles.retention_days":
                return MagicMock(value="5")
            return MagicMock(value="ON")

        mock_client.configurations.get.side_effect = configurations_get

        postgresql = self._build_service_with_client(mock_client)
        servers = postgresql._get_flexible_servers()

        dev_server = servers[AZURE_SUBSCRIPTION_ID][0]
        assert dev_server.log_retention_days == "5"

    def test_unexpected_throttling_error_is_not_silently_collected(self):
        # An unexpected failure reading "connection_throttle.enable" (e.g. a
        # permission, throttling, or transient SDK error) must NOT be turned
        # into connection_throttling=None: that would make the downstream check
        # report the server as having throttling disabled, hiding a collection
        # failure as a security finding. Only ResourceNotFoundError (the
        # parameter genuinely missing) is treated as "not enabled"; anything
        # else isolates to that server, which is dropped rather than fabricated.
        ok = _make_server("ok")
        denied = _make_server("denied")

        mock_client = MagicMock()
        mock_client.servers.list.return_value = [ok, denied]
        server_details = MagicMock()
        server_details.location = "westeurope"
        mock_client.servers.get.return_value = server_details
        mock_client.administrators.list_by_server.return_value = []
        mock_client.firewall_rules.list_by_server.return_value = []

        def configurations_get(resource_group, server_name, key):
            if key == "connection_throttle.enable" and server_name == "denied":
                raise HttpResponseError("(AuthorizationFailed) permission denied")
            return MagicMock(value="ON")

        mock_client.configurations.get.side_effect = configurations_get

        postgresql = self._build_service_with_client(mock_client)
        servers = postgresql._get_flexible_servers()

        collected = servers[AZURE_SUBSCRIPTION_ID]
        # The server whose throttling lookup failed unexpectedly is dropped,
        # not collected with a fabricated connection_throttling=None.
        assert [server.name for server in collected] == ["ok"]
        assert all(server.connection_throttling is not None for server in collected)

    def test_one_server_hard_failure_does_not_drop_others(self):
        # A failure unrelated to a guarded getter (here, fetching the server
        # details) must isolate to that server, not the whole subscription.
        ok = _make_server("ok")
        broken = _make_server("broken")

        mock_client = MagicMock()
        mock_client.servers.list.return_value = [broken, ok]
        mock_client.administrators.list_by_server.return_value = []
        mock_client.firewall_rules.list_by_server.return_value = []
        mock_client.configurations.get.return_value = MagicMock(value="ON")

        def servers_get(resource_group, server_name):
            if server_name == "broken":
                raise Exception("boom: transient failure fetching server details")
            details = MagicMock()
            details.location = "westeurope"
            return details

        mock_client.servers.get.side_effect = servers_get

        postgresql = self._build_service_with_client(mock_client)
        servers = postgresql._get_flexible_servers()

        names = [server.name for server in servers[AZURE_SUBSCRIPTION_ID]]
        assert names == ["ok"]
