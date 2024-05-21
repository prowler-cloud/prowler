from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.postgresql.postgresql_service import Server
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_postgresql_flexible_server_log_disconnections_on:
    def test_no_postgresql_flexible_servers(self):
        postgresql_client = mock.MagicMock
        postgresql_client.flexible_servers = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.postgresql.postgresql_flexible_server_log_disconnections_on.postgresql_flexible_server_log_disconnections_on.postgresql_client",
            new=postgresql_client,
        ):
            from prowler.providers.azure.services.postgresql.postgresql_flexible_server_log_disconnections_on.postgresql_flexible_server_log_disconnections_on import (
                postgresql_flexible_server_log_disconnections_on,
            )

            check = postgresql_flexible_server_log_disconnections_on()
            result = check.execute()
            assert len(result) == 0

    def test_flexible_servers_log_connections_off(self):
        postgresql_client = mock.MagicMock
        postgresql_server_name = "Postgres Flexible Server Name"
        postgresql_server_id = str(uuid4())
        postgresql_client.flexible_servers = {
            AZURE_SUBSCRIPTION_ID: [
                Server(
                    id=postgresql_server_id,
                    name=postgresql_server_name,
                    resource_group="resource_group",
                    require_secure_transport="OFF",
                    log_checkpoints="OFF",
                    log_connections="OFF",
                    log_disconnections="OFF",
                    connection_throttling="OFF",
                    log_retention_days="3",
                    firewall=None,
                    location="location",
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.postgresql.postgresql_flexible_server_log_disconnections_on.postgresql_flexible_server_log_disconnections_on.postgresql_client",
            new=postgresql_client,
        ):
            from prowler.providers.azure.services.postgresql.postgresql_flexible_server_log_disconnections_on.postgresql_flexible_server_log_disconnections_on import (
                postgresql_flexible_server_log_disconnections_on,
            )

            check = postgresql_flexible_server_log_disconnections_on()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Flexible Postgresql server {postgresql_server_name} from subscription {AZURE_SUBSCRIPTION_ID} has log_disconnections disabled"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == postgresql_server_name
            assert result[0].resource_id == postgresql_server_id
            assert result[0].location == "location"

    def test_flexible_servers_log_connections_on(self):
        postgresql_client = mock.MagicMock
        postgresql_server_name = "Postgres Flexible Server Name"
        postgresql_server_id = str(uuid4())
        postgresql_client.flexible_servers = {
            AZURE_SUBSCRIPTION_ID: [
                Server(
                    id=postgresql_server_id,
                    name=postgresql_server_name,
                    resource_group="resource_group",
                    require_secure_transport="OFF",
                    log_checkpoints="ON",
                    log_connections="ON",
                    log_disconnections="ON",
                    connection_throttling="ON",
                    log_retention_days="3",
                    firewall=None,
                    location="location",
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.postgresql.postgresql_flexible_server_log_disconnections_on.postgresql_flexible_server_log_disconnections_on.postgresql_client",
            new=postgresql_client,
        ):
            from prowler.providers.azure.services.postgresql.postgresql_flexible_server_log_disconnections_on.postgresql_flexible_server_log_disconnections_on import (
                postgresql_flexible_server_log_disconnections_on,
            )

            check = postgresql_flexible_server_log_disconnections_on()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Flexible Postgresql server {postgresql_server_name} from subscription {AZURE_SUBSCRIPTION_ID} has log_disconnections enabled"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == postgresql_server_name
            assert result[0].resource_id == postgresql_server_id
            assert result[0].location == "location"
