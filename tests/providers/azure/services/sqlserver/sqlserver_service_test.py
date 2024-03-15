from unittest.mock import patch

from azure.mgmt.sql.models import (
    EncryptionProtector,
    FirewallRule,
    ServerBlobAuditingPolicy,
    ServerSecurityAlertPolicy,
    ServerVulnerabilityAssessment,
    TransparentDataEncryption,
)

from prowler.providers.azure.services.sqlserver.sqlserver_service import (
    Database,
    Server,
    SQLServer,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_provider,
)


def mock_sqlserver_get_sql_servers(_):
    database = Database(
        id="id",
        name="name",
        type="type",
        location="location",
        managed_by="managed_by",
        tde_encryption=TransparentDataEncryption(status="Disabled"),
    )
    return {
        AZURE_SUBSCRIPTION: [
            Server(
                id="id",
                name="name",
                public_network_access="public_network_access",
                minimal_tls_version="minimal_tls_version",
                administrators=None,
                auditing_policies=ServerBlobAuditingPolicy(state="Disabled"),
                firewall_rules=FirewallRule(name="name"),
                encryption_protector=EncryptionProtector(
                    server_key_type="AzureKeyVault"
                ),
                databases=[database],
                vulnerability_assessment=ServerVulnerabilityAssessment(
                    storage_container_path="/subcription_id/resource_group/sql_server"
                ),
                security_alert_policies=ServerSecurityAlertPolicy(state="Disabled"),
            )
        ]
    }


@patch(
    "prowler.providers.azure.services.sqlserver.sqlserver_service.SQLServer.__get_sql_servers__",
    new=mock_sqlserver_get_sql_servers,
)
class Test_SqlServer_Service:
    def test__get_client__(self):
        sql_server = SQLServer(set_mocked_azure_provider())
        assert (
            sql_server.clients[AZURE_SUBSCRIPTION].__class__.__name__
            == "SqlManagementClient"
        )

    def test__get_sql_servers__(self):
        database = Database(
            id="id",
            name="name",
            type="type",
            location="location",
            managed_by="managed_by",
            tde_encryption=TransparentDataEncryption(status="Disabled"),
        )
        sql_server = SQLServer(set_mocked_azure_provider())
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][0].__class__.__name__ == "Server"
        )
        assert sql_server.sql_servers[AZURE_SUBSCRIPTION][0].id == "id"
        assert sql_server.sql_servers[AZURE_SUBSCRIPTION][0].name == "name"
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][0].public_network_access
            == "public_network_access"
        )
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][0].minimal_tls_version
            == "minimal_tls_version"
        )
        assert sql_server.sql_servers[AZURE_SUBSCRIPTION][0].administrators is None
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][
                0
            ].auditing_policies.__class__.__name__
            == "ServerBlobAuditingPolicy"
        )
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][
                0
            ].firewall_rules.__class__.__name__
            == "FirewallRule"
        )
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][
                0
            ].encryption_protector.__class__.__name__
            == "EncryptionProtector"
        )
        assert sql_server.sql_servers[AZURE_SUBSCRIPTION][0].databases == [database]
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][
                0
            ].vulnerability_assessment.__class__.__name__
            == "ServerVulnerabilityAssessment"
        )

    def test__get_databases__(self):
        sql_server = SQLServer(set_mocked_azure_provider())
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][0]
            .databases[0]
            .__class__.__name__
            == "Database"
        )
        assert sql_server.sql_servers[AZURE_SUBSCRIPTION][0].databases[0].id == "id"
        assert sql_server.sql_servers[AZURE_SUBSCRIPTION][0].databases[0].name == "name"
        assert sql_server.sql_servers[AZURE_SUBSCRIPTION][0].databases[0].type == "type"
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][0].databases[0].location
            == "location"
        )
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][0].databases[0].managed_by
            == "managed_by"
        )
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][0]
            .databases[0]
            .tde_encryption.__class__.__name__
            == "TransparentDataEncryption"
        )

    def test__get_transparent_data_encryption__(self):
        sql_server = SQLServer(set_mocked_azure_provider())
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][0]
            .databases[0]
            .tde_encryption.__class__.__name__
            == "TransparentDataEncryption"
        )
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][0]
            .databases[0]
            .tde_encryption.status
            == "Disabled"
        )

    def test__get_encryption_protectors__(self):
        sql_server = SQLServer(set_mocked_azure_provider())
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][
                0
            ].encryption_protector.__class__.__name__
            == "EncryptionProtector"
        )
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][
                0
            ].encryption_protector.server_key_type
            == "AzureKeyVault"
        )

    def test__get_resource_group__(self):
        id = "/subscriptions/subscription_id/resourceGroups/resource_group/providers/Microsoft.Sql/servers/sql_server"
        sql_server = SQLServer(set_mocked_azure_provider())
        assert sql_server.__get_resource_group__(id) == "resource_group"

    def test__get_vulnerability_assessment__(self):
        sql_server = SQLServer(set_mocked_azure_provider())
        storage_container_path = "/subcription_id/resource_group/sql_server"
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][
                0
            ].vulnerability_assessment.__class__.__name__
            == "ServerVulnerabilityAssessment"
        )
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][
                0
            ].vulnerability_assessment.storage_container_path
            == storage_container_path
        )

    def test__get_server_blob_auditing_policies__(self):
        sql_server = SQLServer(set_mocked_azure_provider())
        auditing_policies = ServerBlobAuditingPolicy(state="Disabled")
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][
                0
            ].auditing_policies.__class__.__name__
            == "ServerBlobAuditingPolicy"
        )
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][0].auditing_policies
            == auditing_policies
        )

    def test__get_firewall_rules__(self):
        sql_server = SQLServer(set_mocked_azure_provider())
        firewall_rules = FirewallRule(name="name")
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][
                0
            ].firewall_rules.__class__.__name__
            == "FirewallRule"
        )
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][0].firewall_rules
            == firewall_rules
        )

    def test__get_server_security_alert_policies__(self):
        sql_server = SQLServer(set_mocked_azure_provider())
        security_alert_policies = ServerSecurityAlertPolicy(state="Disabled")
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][
                0
            ].security_alert_policies.__class__.__name__
            == "ServerSecurityAlertPolicy"
        )
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][0].security_alert_policies
            == security_alert_policies
        )
        assert (
            sql_server.sql_servers[AZURE_SUBSCRIPTION][0].security_alert_policies.state
            == "Disabled"
        )
