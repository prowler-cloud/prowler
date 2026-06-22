from unittest import mock
from uuid import uuid4

from azure.mgmt.sql.models import EncryptionProtector, TransparentDataEncryption

from prowler.providers.azure.services.sqlserver.sqlserver_service import (
    Database,
    Server,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)


class Test_sqlserver_tde_encrypted_with_cmk:
    def test_no_sql_servers(self):
        sqlserver_client = mock.MagicMock
        sqlserver_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME
        }
        sqlserver_client.sql_servers = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.sqlserver.sqlserver_tde_encrypted_with_cmk.sqlserver_tde_encrypted_with_cmk.sqlserver_client",
                new=sqlserver_client,
            ),
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_tde_encrypted_with_cmk.sqlserver_tde_encrypted_with_cmk import (
                sqlserver_tde_encrypted_with_cmk,
            )

            check = sqlserver_tde_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 0

    def test_no_sql_servers_databases(self):
        sqlserver_client = mock.MagicMock
        sqlserver_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME
        }
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
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
                    databases=None,
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
                "prowler.providers.azure.services.sqlserver.sqlserver_tde_encrypted_with_cmk.sqlserver_tde_encrypted_with_cmk.sqlserver_client",
                new=sqlserver_client,
            ),
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_tde_encrypted_with_cmk.sqlserver_tde_encrypted_with_cmk import (
                sqlserver_tde_encrypted_with_cmk,
            )

            check = sqlserver_tde_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 0

    def test_sql_servers_encryption_protector_service_managed(self):
        sqlserver_client = mock.MagicMock
        sqlserver_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME
        }
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        database = Database(
            id="id",
            name="name",
            type="type",
            location="location",
            managed_by="managed_by",
            tde_encryption=None,
        )
        sqlserver_client.sql_servers = {
            AZURE_SUBSCRIPTION_ID: [
                Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    location="location",
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=None,
                    firewall_rules=None,
                    databases=[database],
                    encryption_protector=EncryptionProtector(
                        server_key_type="ServiceManaged"
                    ),
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.sqlserver.sqlserver_tde_encrypted_with_cmk.sqlserver_tde_encrypted_with_cmk.sqlserver_client",
                new=sqlserver_client,
            ),
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_tde_encrypted_with_cmk.sqlserver_tde_encrypted_with_cmk import (
                sqlserver_tde_encrypted_with_cmk,
            )

            check = sqlserver_tde_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} has TDE disabled without CMK."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
            assert result[0].location == "location"

    def test_sql_servers_database_encryption_disabled(self):
        sqlserver_client = mock.MagicMock
        sqlserver_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME
        }
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        database = Database(
            id="id",
            name="name",
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
                    location="location",
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=None,
                    firewall_rules=None,
                    databases=[database],
                    encryption_protector=EncryptionProtector(
                        server_key_type="AzureKeyVault"
                    ),
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.sqlserver.sqlserver_tde_encrypted_with_cmk.sqlserver_tde_encrypted_with_cmk.sqlserver_client",
                new=sqlserver_client,
            ),
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_tde_encrypted_with_cmk.sqlserver_tde_encrypted_with_cmk import (
                sqlserver_tde_encrypted_with_cmk,
            )

            check = sqlserver_tde_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} has TDE disabled with CMK."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
            assert result[0].location == "location"

    def test_sql_servers_database_encryption_enabled(self):
        sqlserver_client = mock.MagicMock
        sqlserver_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME
        }
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        database = Database(
            id="id",
            name="name",
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
                    location="location",
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=None,
                    firewall_rules=None,
                    databases=[database],
                    encryption_protector=EncryptionProtector(
                        server_key_type="AzureKeyVault"
                    ),
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.sqlserver.sqlserver_tde_encrypted_with_cmk.sqlserver_tde_encrypted_with_cmk.sqlserver_client",
                new=sqlserver_client,
            ),
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_tde_encrypted_with_cmk.sqlserver_tde_encrypted_with_cmk import (
                sqlserver_tde_encrypted_with_cmk,
            )

            check = sqlserver_tde_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} has TDE enabled with CMK."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
            assert result[0].location == "location"

    def test_sql_servers_master_database_disabled_user_database_enabled(self):
        # System "master" database always reports TDE Disabled in Azure SQL
        # and is not customer-controllable. It must not fail a server whose
        # user databases are correctly encrypted with CMK (PROWLER-1760).
        sqlserver_client = mock.MagicMock
        sqlserver_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME
        }
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        master_database = Database(
            id="master_id",
            name="master",
            type="type",
            location="location",
            managed_by="managed_by",
            tde_encryption=TransparentDataEncryption(status="Disabled"),
        )
        user_database = Database(
            id="user_id",
            name="DynamicBudgets_Intacct",
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
                    location="location",
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=None,
                    firewall_rules=None,
                    databases=[master_database, user_database],
                    encryption_protector=EncryptionProtector(
                        server_key_type="AzureKeyVault"
                    ),
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.sqlserver.sqlserver_tde_encrypted_with_cmk.sqlserver_tde_encrypted_with_cmk.sqlserver_client",
                new=sqlserver_client,
            ),
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_tde_encrypted_with_cmk.sqlserver_tde_encrypted_with_cmk import (
                sqlserver_tde_encrypted_with_cmk,
            )

            check = sqlserver_tde_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} has TDE enabled with CMK."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
            assert result[0].location == "location"

    def test_sql_servers_only_master_database(self):
        # A server whose only database is the system "master" has no user
        # databases to evaluate, so it must not produce a finding.
        sqlserver_client = mock.MagicMock
        sqlserver_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME
        }
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        master_database = Database(
            id="master_id",
            name="MASTER",
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
                    location="location",
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=None,
                    firewall_rules=None,
                    databases=[master_database],
                    encryption_protector=EncryptionProtector(
                        server_key_type="AzureKeyVault"
                    ),
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.sqlserver.sqlserver_tde_encrypted_with_cmk.sqlserver_tde_encrypted_with_cmk.sqlserver_client",
                new=sqlserver_client,
            ),
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_tde_encrypted_with_cmk.sqlserver_tde_encrypted_with_cmk import (
                sqlserver_tde_encrypted_with_cmk,
            )

            check = sqlserver_tde_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 0

    def test_sql_servers_master_disabled_user_database_disabled(self):
        # Filtering out "master" must not mask a genuinely failing user
        # database: a disabled user DB still fails even with CMK.
        sqlserver_client = mock.MagicMock
        sqlserver_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME
        }
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        master_database = Database(
            id="master_id",
            name="master",
            type="type",
            location="location",
            managed_by="managed_by",
            tde_encryption=TransparentDataEncryption(status="Disabled"),
        )
        user_database = Database(
            id="user_id",
            name="DynamicBudgets_Intacct",
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
                    location="location",
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=None,
                    firewall_rules=None,
                    databases=[master_database, user_database],
                    encryption_protector=EncryptionProtector(
                        server_key_type="AzureKeyVault"
                    ),
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.sqlserver.sqlserver_tde_encrypted_with_cmk.sqlserver_tde_encrypted_with_cmk.sqlserver_client",
                new=sqlserver_client,
            ),
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_tde_encrypted_with_cmk.sqlserver_tde_encrypted_with_cmk import (
                sqlserver_tde_encrypted_with_cmk,
            )

            check = sqlserver_tde_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} has TDE disabled with CMK."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
            assert result[0].location == "location"
