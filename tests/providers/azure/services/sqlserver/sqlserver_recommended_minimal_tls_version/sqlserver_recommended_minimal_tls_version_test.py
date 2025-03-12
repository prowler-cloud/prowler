from unittest import mock
from uuid import uuid4

from azure.mgmt.sql.models import TransparentDataEncryption

from prowler.providers.azure.services.sqlserver.sqlserver_service import (
    Database,
    Server,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_sqlserver_recommended_minimal_tls_version:
    def test_no_sql_servers(self):
        sqlserver_client = mock.MagicMock
        sqlserver_client.sql_servers = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.sqlserver.sqlserver_recommended_minimal_tls_version.sqlserver_recommended_minimal_tls_version.sqlserver_client",
                new=sqlserver_client,
            ),
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_recommended_minimal_tls_version.sqlserver_recommended_minimal_tls_version import (
                sqlserver_recommended_minimal_tls_version,
            )

            sqlserver_client.audit_config = {
                "recommended_minimal_tls_versions": ["1.2", "1.3"]
            }

            check = sqlserver_recommended_minimal_tls_version()
            result = check.execute()
            assert len(result) == 0

    def test_sql_servers_deprecated_minimal_tls_version(self):
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
            AZURE_SUBSCRIPTION_ID: [
                Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    public_network_access="",
                    minimal_tls_version="1.0",
                    administrators=None,
                    auditing_policies=None,
                    firewall_rules=None,
                    databases=[database],
                    encryption_protector=None,
                    location="location",
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.sqlserver.sqlserver_recommended_minimal_tls_version.sqlserver_recommended_minimal_tls_version.sqlserver_client",
                new=sqlserver_client,
            ),
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_recommended_minimal_tls_version.sqlserver_recommended_minimal_tls_version import (
                sqlserver_recommended_minimal_tls_version,
            )

            sqlserver_client.audit_config = {
                "recommended_minimal_tls_versions": ["1.2", "1.3"]
            }

            check = sqlserver_recommended_minimal_tls_version()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION_ID} is using TLS version 1.0 as minimal accepted which is not recommended. Please use one of the recommended versions: {', '.join(sqlserver_client.audit_config['recommended_minimal_tls_versions'])}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
            assert result[0].location == "location"

    def test_sql_servers_no_minimal_tls_version(self):
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
            AZURE_SUBSCRIPTION_ID: [
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
                    location="location",
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.sqlserver.sqlserver_recommended_minimal_tls_version.sqlserver_recommended_minimal_tls_version.sqlserver_client",
                new=sqlserver_client,
            ),
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_recommended_minimal_tls_version.sqlserver_recommended_minimal_tls_version import (
                sqlserver_recommended_minimal_tls_version,
            )

            sqlserver_client.audit_config = {
                "recommended_minimal_tls_versions": ["1.2", "1.3"]
            }

            check = sqlserver_recommended_minimal_tls_version()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION_ID} is using TLS version  as minimal accepted which is not recommended. Please use one of the recommended versions: {', '.join(sqlserver_client.audit_config['recommended_minimal_tls_versions'])}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
            assert result[0].location == "location"

    def test_sql_servers_minimal_tls_version(self):
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
            AZURE_SUBSCRIPTION_ID: [
                Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    public_network_access="",
                    minimal_tls_version="1.2",
                    administrators=None,
                    auditing_policies=None,
                    firewall_rules=None,
                    databases=[database],
                    encryption_protector=None,
                    location="location",
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.sqlserver.sqlserver_recommended_minimal_tls_version.sqlserver_recommended_minimal_tls_version.sqlserver_client",
                new=sqlserver_client,
            ),
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_recommended_minimal_tls_version.sqlserver_recommended_minimal_tls_version import (
                sqlserver_recommended_minimal_tls_version,
            )

            sqlserver_client.audit_config = {
                "recommended_minimal_tls_versions": ["1.2", "1.3"]
            }

            check = sqlserver_recommended_minimal_tls_version()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION_ID} is using version 1.2 as minimal accepted which is recommended."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
            assert result[0].location == "location"
