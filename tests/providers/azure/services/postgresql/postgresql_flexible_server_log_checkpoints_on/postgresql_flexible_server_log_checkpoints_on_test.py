from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.postgresql.postgresql_service import Server

AZURE_SUBSCRIPTION = str(uuid4())


class Test_postgresql_flexible_server_log_checkpoints_on:
    def test_no_postgresql_flexible_servers(self):
        postgresql_client = mock.MagicMock
        postgresql_client.flexible_servers = {}

        with mock.patch(
            "prowler.providers.azure.services.postgresql.postgresql_flexible_server_log_checkpoints_on.postgresql_flexible_server_log_checkpoints_on.postgresql_client",
            new=postgresql_client,
        ):
            from prowler.providers.azure.services.postgresql.postgresql_flexible_server_log_checkpoints_on.postgresql_flexible_server_log_checkpoints_on import (
                postgresql_flexible_server_log_checkpoints_on,
            )

            check = postgresql_flexible_server_log_checkpoints_on()
            result = check.execute()
            assert len(result) == 0

    def test_flexible_servers_log_checkpoints_off(self):
        postgresql_client = mock.MagicMock
        postgresql_server_name = "Postgres Flexible Server Name"
        postgresql_server_id = str(uuid4())
        postgresql_client.flexible_servers = {
            AZURE_SUBSCRIPTION: [
                Server(
                    id=postgresql_server_id,
                    name=postgresql_server_name,
                    resource_group="resource_group",
                    require_secure_transport="ON",
                    log_checkpoints="OFF",
                    log_connections="ON",
                    log_disconnections="ON",
                    connection_throttling="ON",
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.postgresql.postgresql_flexible_server_log_checkpoints_on.postgresql_flexible_server_log_checkpoints_on.postgresql_client",
            new=postgresql_client,
        ):
            from prowler.providers.azure.services.postgresql.postgresql_flexible_server_log_checkpoints_on.postgresql_flexible_server_log_checkpoints_on import (
                postgresql_flexible_server_log_checkpoints_on,
            )

            check = postgresql_flexible_server_log_checkpoints_on()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Flexible Postgresql server {postgresql_server_name} from subscription {AZURE_SUBSCRIPTION} has log_checkpoints disabled"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == postgresql_server_name
            assert result[0].resource_id == postgresql_server_id

    def test_flexible_servers_log_checkpoints_on(self):
        postgresql_client = mock.MagicMock
        postgresql_server_name = "Postgres Flexible Server Name"
        postgresql_server_id = str(uuid4())
        postgresql_client.flexible_servers = {
            AZURE_SUBSCRIPTION: [
                Server(
                    id=postgresql_server_id,
                    name=postgresql_server_name,
                    resource_group="resource_group",
                    require_secure_transport="ON",
                    log_checkpoints="ON",
                    log_connections="ON",
                    log_disconnections="ON",
                    connection_throttling="ON",
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.postgresql.postgresql_flexible_server_log_checkpoints_on.postgresql_flexible_server_log_checkpoints_on.postgresql_client",
            new=postgresql_client,
        ):
            from prowler.providers.azure.services.postgresql.postgresql_flexible_server_log_checkpoints_on.postgresql_flexible_server_log_checkpoints_on import (
                postgresql_flexible_server_log_checkpoints_on,
            )

            check = postgresql_flexible_server_log_checkpoints_on()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Flexible Postgresql server {postgresql_server_name} from subscription {AZURE_SUBSCRIPTION} has log_checkpoints enabled"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == postgresql_server_name
            assert result[0].resource_id == postgresql_server_id
