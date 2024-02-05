from unittest import mock
from uuid import uuid4

from azure.mgmt.sql.models import TransparentDataEncryption

from prowler.providers.azure.services.sqlserver.sqlserver_service import (
    Database,
    Server,
)

AZURE_SUBSCRIPTION = str(uuid4())


class Test_sqlserver_tde_encryption_enabled:
    def test_no_sql_servers(self):
        sqlserver_client = mock.MagicMock
        sqlserver_client.sql_servers = {}

        with mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_tde_encryption_enabled.sqlserver_tde_encryption_enabled.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_tde_encryption_enabled.sqlserver_tde_encryption_enabled import (
                sqlserver_tde_encryption_enabled,
            )

            check = sqlserver_tde_encryption_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_no_sql_servers_databases(self):
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
                    auditing_policies=None,
                    firewall_rules=None,
                    databases=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_tde_encryption_enabled.sqlserver_tde_encryption_enabled.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_tde_encryption_enabled.sqlserver_tde_encryption_enabled import (
                sqlserver_tde_encryption_enabled,
            )

            check = sqlserver_tde_encryption_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_sql_servers_database_encryption_disabled(self):
        sqlserver_client = mock.MagicMock
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        database_name = "Database Name"
        database_id = str(uuid4())
        database = Database(
            id=database_id,
            name=database_name,
            type="type",
            location="location",
            managed_by="managed_by",
            tde_encryption=TransparentDataEncryption(status="Disabled"),
        )
        sqlserver_client.sql_servers = {
            AZURE_SUBSCRIPTION: [
                Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=None,
                    firewall_rules=None,
                    databases=[database],
                    encryption_protector=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_tde_encryption_enabled.sqlserver_tde_encryption_enabled.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_tde_encryption_enabled.sqlserver_tde_encryption_enabled import (
                sqlserver_tde_encryption_enabled,
            )

            check = sqlserver_tde_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Database {database_name} from SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION} has TDE disabled"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == database_name
            assert result[0].resource_id == database_id

    def test_sql_servers_database_encryption_enabled(self):
        sqlserver_client = mock.MagicMock
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        database_name = "Database Name"
        database_id = str(uuid4())
        database = Database(
            id=database_id,
            name=database_name,
            type="type",
            location="location",
            managed_by="managed_by",
            tde_encryption=TransparentDataEncryption(status="Enabled"),
        )
        sqlserver_client.sql_servers = {
            AZURE_SUBSCRIPTION: [
                Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=None,
                    firewall_rules=None,
                    databases=[database],
                    encryption_protector=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_tde_encryption_enabled.sqlserver_tde_encryption_enabled.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_tde_encryption_enabled.sqlserver_tde_encryption_enabled import (
                sqlserver_tde_encryption_enabled,
            )

            check = sqlserver_tde_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Database {database_name} from SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION} has TDE enabled"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == database_name
            assert result[0].resource_id == database_id
