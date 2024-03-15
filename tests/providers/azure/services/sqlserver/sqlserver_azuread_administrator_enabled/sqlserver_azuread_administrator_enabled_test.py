from unittest import mock
from uuid import uuid4

from azure.mgmt.sql.models import ServerExternalAdministrator

from prowler.providers.azure.services.sqlserver.sqlserver_service import Server
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_provider,
)


class Test_sqlserver_azuread_administrator_enabled:
    def test_no_sql_servers(self):
        sqlserver_client = mock.MagicMock
        sqlserver_client.sql_servers = {}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_azuread_administrator_enabled.sqlserver_azuread_administrator_enabled.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_azuread_administrator_enabled.sqlserver_azuread_administrator_enabled import (
                sqlserver_azuread_administrator_enabled,
            )

            check = sqlserver_azuread_administrator_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_sql_servers_azuread_no_administrator(self):
        sqlserver_client = mock.MagicMock
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        sqlserver_client.sql_servers = {
            AZURE_SUBSCRIPTION: [
                Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=[],
                    firewall_rules=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_azuread_administrator_enabled.sqlserver_azuread_administrator_enabled.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_azuread_administrator_enabled.sqlserver_azuread_administrator_enabled import (
                sqlserver_azuread_administrator_enabled,
            )

            check = sqlserver_azuread_administrator_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION} does not have an Active Directory administrator."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id

    def test_sql_servers_azuread_administrator_no_active_directory(self):
        sqlserver_client = mock.MagicMock
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        sqlserver_client.sql_servers = {
            AZURE_SUBSCRIPTION: [
                Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=ServerExternalAdministrator(
                        administrator_type="No ActiveDirectory"
                    ),
                    auditing_policies=[],
                    firewall_rules=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_azuread_administrator_enabled.sqlserver_azuread_administrator_enabled.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_azuread_administrator_enabled.sqlserver_azuread_administrator_enabled import (
                sqlserver_azuread_administrator_enabled,
            )

            check = sqlserver_azuread_administrator_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION} does not have an Active Directory administrator."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id

    def test_sql_servers_azuread_administrator_active_directory(self):
        sqlserver_client = mock.MagicMock
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        sqlserver_client.sql_servers = {
            AZURE_SUBSCRIPTION: [
                Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=ServerExternalAdministrator(
                        administrator_type="ActiveDirectory"
                    ),
                    auditing_policies=[],
                    firewall_rules=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_azuread_administrator_enabled.sqlserver_azuread_administrator_enabled.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_azuread_administrator_enabled.sqlserver_azuread_administrator_enabled import (
                sqlserver_azuread_administrator_enabled,
            )

            check = sqlserver_azuread_administrator_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION} has an Active Directory administrator."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
