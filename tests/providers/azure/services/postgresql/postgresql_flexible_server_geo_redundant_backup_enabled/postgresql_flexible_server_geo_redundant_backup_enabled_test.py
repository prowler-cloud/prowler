from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.postgresql.postgresql_service import Server
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)


def _make_server(server_id, server_name, geo_redundant_backup):
    return Server(
        id=server_id,
        name=server_name,
        resource_group="resource_group",
        location="eastus",
        require_secure_transport="ON",
        active_directory_auth="Enabled",
        entra_id_admins=[],
        log_checkpoints="ON",
        log_connections="ON",
        log_disconnections="ON",
        connection_throttling="ON",
        log_retention_days="3",
        firewall=[],
        geo_redundant_backup=geo_redundant_backup,
    )


class Test_postgresql_flexible_server_geo_redundant_backup_enabled:
    def test_no_postgresql_flexible_servers(self):
        postgresql_client = mock.MagicMock
        postgresql_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME
        }
        postgresql_client.flexible_servers = {}

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

            check = postgresql_flexible_server_geo_redundant_backup_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_postgresql_geo_redundant_backup_disabled(self):
        server_id = str(uuid4())
        server_name = "test-server"
        postgresql_client = mock.MagicMock
        postgresql_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME
        }
        postgresql_client.flexible_servers = {
            AZURE_SUBSCRIPTION_ID: [_make_server(server_id, server_name, "Disabled")]
        }

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

            check = postgresql_flexible_server_geo_redundant_backup_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Flexible Postgresql server {server_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} does not have geo-redundant backup enabled."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == server_name
            assert result[0].resource_id == server_id
            assert result[0].location == "eastus"

    def test_postgresql_geo_redundant_backup_enabled(self):
        server_id = str(uuid4())
        server_name = "test-server"
        postgresql_client = mock.MagicMock
        postgresql_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME
        }
        postgresql_client.flexible_servers = {
            AZURE_SUBSCRIPTION_ID: [_make_server(server_id, server_name, "Enabled")]
        }

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

            check = postgresql_flexible_server_geo_redundant_backup_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Flexible Postgresql server {server_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} has geo-redundant backup enabled."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == server_name
            assert result[0].resource_id == server_id
            assert result[0].location == "eastus"
