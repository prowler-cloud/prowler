from unittest import mock
from uuid import uuid4

from azure.mgmt.sql.models import ServerSecurityAlertPolicy

from prowler.providers.azure.services.sqlserver.sqlserver_service import Server

AZURE_SUBSCRIPTION = str(uuid4())


class Test_sqlserver_microsoft_defender_enabled:
    def test_no_sql_servers(self):
        sqlserver_client = mock.MagicMock
        sqlserver_client.sql_servers = {}

        with mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_microsoft_defender_enabled.sqlserver_microsoft_defender_enabled.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_microsoft_defender_enabled.sqlserver_microsoft_defender_enabled import (
                sqlserver_microsoft_defender_enabled,
            )

            check = sqlserver_microsoft_defender_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_sql_servers_no_security_alert_policies(self):
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
                    security_alert_policies=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_microsoft_defender_enabled.sqlserver_microsoft_defender_enabled.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_microsoft_defender_enabled.sqlserver_microsoft_defender_enabled import (
                sqlserver_microsoft_defender_enabled,
            )

            check = sqlserver_microsoft_defender_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_sql_servers_microsoft_defender_disabled(self):
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
                    security_alert_policies=ServerSecurityAlertPolicy(state="Disabled"),
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_microsoft_defender_enabled.sqlserver_microsoft_defender_enabled.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_microsoft_defender_enabled.sqlserver_microsoft_defender_enabled import (
                sqlserver_microsoft_defender_enabled,
            )

            check = sqlserver_microsoft_defender_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION} has microsoft defender disabled."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id

    def test_sql_servers_microsoft_defender_enabled(self):
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
                    security_alert_policies=ServerSecurityAlertPolicy(state="Enabled"),
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_microsoft_defender_enabled.sqlserver_microsoft_defender_enabled.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_microsoft_defender_enabled.sqlserver_microsoft_defender_enabled import (
                sqlserver_microsoft_defender_enabled,
            )

            check = sqlserver_microsoft_defender_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION} has microsoft defender enabled."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
