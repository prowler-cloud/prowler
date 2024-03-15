from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.postgresql.postgresql_service import (
    Firewall,
    Server,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_provider,
)


class Test_postgresql_flexible_server_allow_access_services_disabled:
    def test_no_postgresql_flexible_servers(self):
        postgresql_client = mock.MagicMock
        postgresql_client.flexible_servers = {}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.postgresql.postgresql_flexible_server_allow_access_services_disabled.postgresql_flexible_server_allow_access_services_disabled.postgresql_client",
            new=postgresql_client,
        ):
            from prowler.providers.azure.services.postgresql.postgresql_flexible_server_allow_access_services_disabled.postgresql_flexible_server_allow_access_services_disabled import (
                postgresql_flexible_server_allow_access_services_disabled,
            )

            check = postgresql_flexible_server_allow_access_services_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_flexible_servers_allow_public_access(self):
        postgresql_client = mock.MagicMock
        postgresql_server_name = "Postgres Flexible Server Name"
        postgresql_server_id = str(uuid4())
        firewall = Firewall(
            id=str(uuid4()),
            name="firewall_name",
            start_ip="0.0.0.0",
            end_ip="0.0.0.0",
        )
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
                    log_retention_days="3",
                    firewall=[firewall],
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.postgresql.postgresql_flexible_server_allow_access_services_disabled.postgresql_flexible_server_allow_access_services_disabled.postgresql_client",
            new=postgresql_client,
        ):
            from prowler.providers.azure.services.postgresql.postgresql_flexible_server_allow_access_services_disabled.postgresql_flexible_server_allow_access_services_disabled import (
                postgresql_flexible_server_allow_access_services_disabled,
            )

            check = postgresql_flexible_server_allow_access_services_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Flexible Postgresql server {postgresql_server_name} from subscription {AZURE_SUBSCRIPTION} has allow public access from any Azure service enabled"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == postgresql_server_name
            assert result[0].resource_id == postgresql_server_id

    def test_flexible_servers_dont_allow_public_access(self):
        postgresql_client = mock.MagicMock
        postgresql_server_name = "Postgres Flexible Server Name"
        postgresql_server_id = str(uuid4())
        firewall = Firewall(
            id=str(uuid4()),
            name="firewall_name",
            start_ip="1.1.1.1",
            end_ip="1.1.1.1",
        )
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
                    log_retention_days="3",
                    firewall=[firewall],
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.postgresql.postgresql_flexible_server_allow_access_services_disabled.postgresql_flexible_server_allow_access_services_disabled.postgresql_client",
            new=postgresql_client,
        ):
            from prowler.providers.azure.services.postgresql.postgresql_flexible_server_allow_access_services_disabled.postgresql_flexible_server_allow_access_services_disabled import (
                postgresql_flexible_server_allow_access_services_disabled,
            )

            check = postgresql_flexible_server_allow_access_services_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Flexible Postgresql server {postgresql_server_name} from subscription {AZURE_SUBSCRIPTION} has allow public access from any Azure service disabled"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == postgresql_server_name
            assert result[0].resource_id == postgresql_server_id
