from unittest.mock import patch

from prowler.providers.azure.services.mysql.mysql_service import MySQL, Server
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_audit_info,
)


def mock_mysql_get_servers(_):
    return {
        AZURE_SUBSCRIPTION: {
            "test": Server(
                resource_id="/subscriptions/resource_id",
                location="location",
                version="version",
                ssl_enforcement="Enabled",
                minimal_tls_version="TLS1_2",
            )
        }
    }


@patch(
    "prowler.providers.azure.services.mysql.mysql_service.MySQL.__get_servers__",
    new=mock_mysql_get_servers,
)
class Test_MySQL_Service:
    def test__get_client__(self):
        mysql = MySQL(set_mocked_azure_audit_info())
        assert (
            mysql.clients[AZURE_SUBSCRIPTION].__class__.__name__
            == "MySQLManagementClient"
        )

    def test__get_subscriptions__(self):
        mysql = MySQL(set_mocked_azure_audit_info())
        assert mysql.subscriptions.__class__.__name__ == "dict"

    def test__get_servers__(self):
        mysql = MySQL(set_mocked_azure_audit_info())
        assert len(mysql.servers) == 1
        assert (
            mysql.servers[AZURE_SUBSCRIPTION]["test"].resource_id
            == "/subscriptions/resource_id"
        )
        assert mysql.servers[AZURE_SUBSCRIPTION]["test"].location == "location"
        assert mysql.servers[AZURE_SUBSCRIPTION]["test"].version == "version"
        assert mysql.servers[AZURE_SUBSCRIPTION]["test"].ssl_enforcement == "Enabled"
        assert mysql.servers[AZURE_SUBSCRIPTION]["test"].minimal_tls_version == "TLS1_2"
