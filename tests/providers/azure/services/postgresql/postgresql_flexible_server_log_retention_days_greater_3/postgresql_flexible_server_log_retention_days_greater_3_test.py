from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.postgresql.postgresql_service import Server

AZURE_SUBSCRIPTION = str(uuid4())


class Test_postgresql_flexible_server_log_retention_days_greater_3:
    def test_no_postgresql_flexible_servers(self):
        postgresql_client = mock.MagicMock
        postgresql_client.flexible_servers = {}

        with mock.patch(
            "prowler.providers.azure.services.postgresql.postgresql_flexible_server_log_retention_days_greater_3.postgresql_flexible_server_log_retention_days_greater_3.postgresql_client",
            new=postgresql_client,
        ):
            from prowler.providers.azure.services.postgresql.postgresql_flexible_server_log_retention_days_greater_3.postgresql_flexible_server_log_retention_days_greater_3 import (
                postgresql_flexible_server_log_retention_days_greater_3,
            )

            check = postgresql_flexible_server_log_retention_days_greater_3()
            result = check.execute()
            assert len(result) == 0

    def test_flexible_servers_no_log_retention_days(self):
        postgresql_client = mock.MagicMock
        postgresql_server_name = "Postgres Flexible Server Name"
        postgresql_server_id = str(uuid4())
        postgresql_client.flexible_servers = {
            AZURE_SUBSCRIPTION: [
                Server(
                    id=postgresql_server_id,
                    name=postgresql_server_name,
                    resource_group="resource_group",
                    require_secure_transport="OFF",
                    log_checkpoints="OFF",
                    log_connections="OFF",
                    log_disconnections="OFF",
                    connection_throttling="OFF",
                    log_retention_days=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.postgresql.postgresql_flexible_server_log_retention_days_greater_3.postgresql_flexible_server_log_retention_days_greater_3.postgresql_client",
            new=postgresql_client,
        ):
            from prowler.providers.azure.services.postgresql.postgresql_flexible_server_log_retention_days_greater_3.postgresql_flexible_server_log_retention_days_greater_3 import (
                postgresql_flexible_server_log_retention_days_greater_3,
            )

            check = postgresql_flexible_server_log_retention_days_greater_3()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Flexible Postgresql server {postgresql_server_name} from subscription {AZURE_SUBSCRIPTION} has log_retention disabled"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == postgresql_server_name
            assert result[0].resource_id == postgresql_server_id

    def test_flexible_servers_log_retention_days_3(self):
        postgresql_client = mock.MagicMock
        postgresql_server_name = "Postgres Flexible Server Name"
        postgresql_server_id = str(uuid4())
        log_retention_days = "3"
        postgresql_client.flexible_servers = {
            AZURE_SUBSCRIPTION: [
                Server(
                    id=postgresql_server_id,
                    name=postgresql_server_name,
                    resource_group="resource_group",
                    require_secure_transport="OFF",
                    log_checkpoints="OFF",
                    log_connections="OFF",
                    log_disconnections="OFF",
                    connection_throttling="OFF",
                    log_retention_days=log_retention_days,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.postgresql.postgresql_flexible_server_log_retention_days_greater_3.postgresql_flexible_server_log_retention_days_greater_3.postgresql_client",
            new=postgresql_client,
        ):
            from prowler.providers.azure.services.postgresql.postgresql_flexible_server_log_retention_days_greater_3.postgresql_flexible_server_log_retention_days_greater_3 import (
                postgresql_flexible_server_log_retention_days_greater_3,
            )

            check = postgresql_flexible_server_log_retention_days_greater_3()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Flexible Postgresql server {postgresql_server_name} from subscription {AZURE_SUBSCRIPTION} has log_retention set to {log_retention_days}"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == postgresql_server_name
            assert result[0].resource_id == postgresql_server_id

    def test_flexible_servers_log_retention_days_4(self):
        postgresql_client = mock.MagicMock
        postgresql_server_name = "Postgres Flexible Server Name"
        postgresql_server_id = str(uuid4())
        log_retention_days = "4"
        postgresql_client.flexible_servers = {
            AZURE_SUBSCRIPTION: [
                Server(
                    id=postgresql_server_id,
                    name=postgresql_server_name,
                    resource_group="resource_group",
                    require_secure_transport="OFF",
                    log_checkpoints="OFF",
                    log_connections="OFF",
                    log_disconnections="OFF",
                    connection_throttling="OFF",
                    log_retention_days=log_retention_days,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.postgresql.postgresql_flexible_server_log_retention_days_greater_3.postgresql_flexible_server_log_retention_days_greater_3.postgresql_client",
            new=postgresql_client,
        ):
            from prowler.providers.azure.services.postgresql.postgresql_flexible_server_log_retention_days_greater_3.postgresql_flexible_server_log_retention_days_greater_3 import (
                postgresql_flexible_server_log_retention_days_greater_3,
            )

            check = postgresql_flexible_server_log_retention_days_greater_3()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Flexible Postgresql server {postgresql_server_name} from subscription {AZURE_SUBSCRIPTION} has log_retention set to {log_retention_days}"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == postgresql_server_name
            assert result[0].resource_id == postgresql_server_id

    def test_flexible_servers_log_retention_days_8(self):
        postgresql_client = mock.MagicMock
        postgresql_server_name = "Postgres Flexible Server Name"
        postgresql_server_id = str(uuid4())
        log_retention_days = "8"
        postgresql_client.flexible_servers = {
            AZURE_SUBSCRIPTION: [
                Server(
                    id=postgresql_server_id,
                    name=postgresql_server_name,
                    resource_group="resource_group",
                    require_secure_transport="OFF",
                    log_checkpoints="OFF",
                    log_connections="OFF",
                    log_disconnections="OFF",
                    connection_throttling="OFF",
                    log_retention_days=log_retention_days,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.postgresql.postgresql_flexible_server_log_retention_days_greater_3.postgresql_flexible_server_log_retention_days_greater_3.postgresql_client",
            new=postgresql_client,
        ):
            from prowler.providers.azure.services.postgresql.postgresql_flexible_server_log_retention_days_greater_3.postgresql_flexible_server_log_retention_days_greater_3 import (
                postgresql_flexible_server_log_retention_days_greater_3,
            )

            check = postgresql_flexible_server_log_retention_days_greater_3()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Flexible Postgresql server {postgresql_server_name} from subscription {AZURE_SUBSCRIPTION} has log_retention set to {log_retention_days}"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == postgresql_server_name
            assert result[0].resource_id == postgresql_server_id
