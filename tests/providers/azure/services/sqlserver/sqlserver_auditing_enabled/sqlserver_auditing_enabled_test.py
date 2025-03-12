from unittest import mock
from uuid import uuid4

from azure.mgmt.sql.models import (
    FirewallRule,
    ServerBlobAuditingPolicy,
    ServerExternalAdministrator,
)

from prowler.providers.azure.services.sqlserver.sqlserver_service import Server
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_sqlserver_auditing_enabled:
    def test_no_sql_servers(self):
        sqlserver_client = mock.MagicMock
        sqlserver_client.sql_servers = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_auditing_enabled.sqlserver_auditing_enabled.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_auditing_enabled.sqlserver_auditing_enabled import (
                sqlserver_auditing_enabled,
            )

            check = sqlserver_auditing_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_sql_servers_auditing_disabled(self):
        sqlserver_client = mock.MagicMock
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        sqlserver_client.sql_servers = {
            AZURE_SUBSCRIPTION_ID: [
                Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=ServerExternalAdministrator(),
                    auditing_policies=[ServerBlobAuditingPolicy(state="Disabled")],
                    firewall_rules=FirewallRule(),
                    location="location",
                ),
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_auditing_enabled.sqlserver_auditing_enabled.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_auditing_enabled.sqlserver_auditing_enabled import (
                sqlserver_auditing_enabled,
            )

            check = sqlserver_auditing_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION_ID} does not have any auditing policy configured."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
            assert result[0].location == "location"

    def test_sql_servers_auditing_enabled(self):
        sqlserver_client = mock.MagicMock
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        sqlserver_client.sql_servers = {
            AZURE_SUBSCRIPTION_ID: [
                Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=ServerExternalAdministrator(),
                    auditing_policies=[ServerBlobAuditingPolicy(state="Enabled")],
                    firewall_rules=FirewallRule(),
                    location="location",
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_auditing_enabled.sqlserver_auditing_enabled.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_auditing_enabled.sqlserver_auditing_enabled import (
                sqlserver_auditing_enabled,
            )

            check = sqlserver_auditing_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION_ID} has a auditing policy configured."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
            assert result[0].location == "location"
