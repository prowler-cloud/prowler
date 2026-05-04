from unittest import mock

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_postgresql_flexible_server_geo_redundant_backup_enabled:
    def test_no_subscriptions(self):
        postgresql_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.postgresql.postgresql_flexible_server_geo_redundant_backup_enabled.postgresql_flexible_server_geo_redundant_backup_enabled.postgresql_client",
                new=postgresql_client,
            ),
        ):
            from prowler.providers.azure.services.postgresql.postgresql_flexible_server_geo_redundant_backup_enabled.postgresql_flexible_server_geo_redundant_backup_enabled import (
                postgresql_flexible_server_geo_redundant_backup_enabled,
            )

            postgresql_client.flexible_servers = {}

            check = postgresql_flexible_server_geo_redundant_backup_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_pass(self):
        postgresql_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.postgresql.postgresql_flexible_server_geo_redundant_backup_enabled.postgresql_flexible_server_geo_redundant_backup_enabled.postgresql_client",
                new=postgresql_client,
            ),
        ):
            from prowler.providers.azure.services.postgresql.postgresql_flexible_server_geo_redundant_backup_enabled.postgresql_flexible_server_geo_redundant_backup_enabled import (
                postgresql_flexible_server_geo_redundant_backup_enabled,
            )
            from prowler.providers.azure.services.postgresql.postgresql_service import Server

            postgresql_client.flexible_servers = {AZURE_SUBSCRIPTION_ID: [Server(id="/sub/rg/server1", name="test-server", resource_group="rg1", location="eastus", require_secure_transport="ON", active_directory_auth="Enabled", entra_id_admins=[], log_checkpoints="ON", log_connections="ON", log_disconnections="ON", connection_throttling="ON", log_retention_days="3", firewall=[], geo_redundant_backup="Enabled")]}

            check = postgresql_flexible_server_geo_redundant_backup_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_fail(self):
        postgresql_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.postgresql.postgresql_flexible_server_geo_redundant_backup_enabled.postgresql_flexible_server_geo_redundant_backup_enabled.postgresql_client",
                new=postgresql_client,
            ),
        ):
            from prowler.providers.azure.services.postgresql.postgresql_flexible_server_geo_redundant_backup_enabled.postgresql_flexible_server_geo_redundant_backup_enabled import (
                postgresql_flexible_server_geo_redundant_backup_enabled,
            )
            from prowler.providers.azure.services.postgresql.postgresql_service import Server

            postgresql_client.flexible_servers = {AZURE_SUBSCRIPTION_ID: [Server(id="/sub/rg/server1", name="test-server", resource_group="rg1", location="eastus", require_secure_transport="ON", active_directory_auth="Enabled", entra_id_admins=[], log_checkpoints="ON", log_connections="ON", log_disconnections="ON", connection_throttling="ON", log_retention_days="3", firewall=[], geo_redundant_backup="Disabled")]}

            check = postgresql_flexible_server_geo_redundant_backup_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
