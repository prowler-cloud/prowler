from unittest import mock
from uuid import uuid4

from azure.mgmt.sql.models import ServerBlobAuditingPolicy

from prowler.providers.azure.services.sqlserver.sqlserver_service import SQL_Server
from tests.providers.azure.azure_fixtures import AZURE_SUSCRIPTION


class Test_sqlserver_auditing_retention_90_days:
    def test_no_sql_servers(self):
        sqlserver_client = mock.MagicMock
        sqlserver_client.sql_servers = {}

        with mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days import (
                sqlserver_auditing_retention_90_days,
            )

            check = sqlserver_auditing_retention_90_days()
            result = check.execute()
            assert len(result) == 0

    def test_sql_servers_auditing_policy_disabled(self):
        sqlserver_client = mock.MagicMock
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        sqlserver_client.sql_servers = {
            AZURE_SUSCRIPTION: [
                SQL_Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=[ServerBlobAuditingPolicy(state="Disabled")],
                    firewall_rules=None,
                    databases=None,
                    encryption_protector=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days import (
                sqlserver_auditing_retention_90_days,
            )

            check = sqlserver_auditing_retention_90_days()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUSCRIPTION} has auditing disabled."
            )
            assert result[0].subscription == AZURE_SUSCRIPTION
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id

    def test_sql_servers_auditing_retention_less_than_90_days(self):
        sqlserver_client = mock.MagicMock
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        sqlserver_client.sql_servers = {
            AZURE_SUSCRIPTION: [
                SQL_Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=[
                        ServerBlobAuditingPolicy(state="Enabled", retention_days=89)
                    ],
                    firewall_rules=None,
                    databases=None,
                    encryption_protector=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days import (
                sqlserver_auditing_retention_90_days,
            )

            check = sqlserver_auditing_retention_90_days()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUSCRIPTION} has auditing retention less than 91 days."
            )
            assert result[0].subscription == AZURE_SUSCRIPTION
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id

    def test_sql_servers_auditing_retention_greater_than_90_days(self):
        sqlserver_client = mock.MagicMock
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        sqlserver_client.sql_servers = {
            AZURE_SUSCRIPTION: [
                SQL_Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=[
                        ServerBlobAuditingPolicy(state="Enabled", retention_days=91)
                    ],
                    firewall_rules=None,
                    databases=None,
                    encryption_protector=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days import (
                sqlserver_auditing_retention_90_days,
            )

            check = sqlserver_auditing_retention_90_days()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUSCRIPTION} has auditing retention greater than 90 days."
            )
            assert result[0].subscription == AZURE_SUSCRIPTION
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id

    def test_sql_servers_two_auditing_policies_with_auditing_retention_greater_than_90_days(
        self,
    ):
        sqlserver_client = mock.MagicMock
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        sqlserver_client.sql_servers = {
            AZURE_SUSCRIPTION: [
                SQL_Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=[
                        ServerBlobAuditingPolicy(state="Enabled", retention_days=91),
                        ServerBlobAuditingPolicy(state="Enabled", retention_days=100),
                    ],
                    firewall_rules=None,
                    databases=None,
                    encryption_protector=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days import (
                sqlserver_auditing_retention_90_days,
            )

            check = sqlserver_auditing_retention_90_days()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUSCRIPTION} has auditing retention greater than 90 days."
            )
            assert result[0].subscription == AZURE_SUSCRIPTION
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id

    def test_sql_servers_two_auditing_policies_with_one_auditing_retention_less_than_90_days(
        self,
    ):
        sqlserver_client = mock.MagicMock
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        sqlserver_client.sql_servers = {
            AZURE_SUSCRIPTION: [
                SQL_Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=[
                        ServerBlobAuditingPolicy(state="Enabled", retention_days=91),
                        ServerBlobAuditingPolicy(state="Enabled", retention_days=80),
                    ],
                    firewall_rules=None,
                    databases=None,
                    encryption_protector=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_auditing_retention_90_days.sqlserver_auditing_retention_90_days import (
                sqlserver_auditing_retention_90_days,
            )

            check = sqlserver_auditing_retention_90_days()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUSCRIPTION} has auditing retention less than 91 days."
            )
            assert result[0].subscription == AZURE_SUSCRIPTION
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
