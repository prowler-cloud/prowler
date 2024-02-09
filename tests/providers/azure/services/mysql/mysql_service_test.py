from unittest.mock import patch

from prowler.providers.azure.services.mysql.mysql_service import (
    Configuration,
    MySQL,
    Server,
)
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
                resource_group="resource_group",
            )
        }
    }


def mock_mysql_get_configurations(_):
    return {
        AZURE_SUBSCRIPTION: {
            "test": Configuration(
                resource_id="/subscriptions/resource_id",
                server_name="test",
                description="description",
                value="value",
            )
        }
    }


@patch(
    "prowler.providers.azure.services.mysql.mysql_service.MySQL.__get_servers__",
    new=mock_mysql_get_servers,
)
@patch(
    "prowler.providers.azure.services.mysql.mysql_service.MySQL.__get_configurations__",
    new=mock_mysql_get_configurations,
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
        assert (
            mysql.servers[AZURE_SUBSCRIPTION]["test"].resource_group == "resource_group"
        )

    def test__get_configurations__(self):
        mysql = MySQL(set_mocked_azure_audit_info())
        assert len(mysql.configurations) == 1
        assert (
            mysql.configurations[AZURE_SUBSCRIPTION]["test"].resource_id
            == "/subscriptions/resource_id"
        )
        assert mysql.configurations[AZURE_SUBSCRIPTION]["test"].server_name == "test"
        assert (
            mysql.configurations[AZURE_SUBSCRIPTION]["test"].description
            == "description"
        )
        assert mysql.configurations[AZURE_SUBSCRIPTION]["test"].value == "value"
