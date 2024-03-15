from unittest.mock import patch

from prowler.providers.azure.services.mysql.mysql_service import (
    Configuration,
    FlexibleServer,
    MySQL,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_provider,
)


def mock_mysql_get_servers(_):
    return {
        AZURE_SUBSCRIPTION: {
            "test": FlexibleServer(
                resource_id="/subscriptions/resource_id",
                location="location",
                version="version",
                configurations={
                    "test": Configuration(
                        resource_id="/subscriptions/test/resource_id",
                        description="description",
                        value="value",
                    )
                },
            )
        }
    }


def mock_mysql_get_configurations(_):
    return {
        "test": Configuration(
            resource_id="/subscriptions/resource_id",
            description="description",
            value="value",
        )
    }


@patch(
    "prowler.providers.azure.services.mysql.mysql_service.MySQL.__get_flexible_servers__",
    new=mock_mysql_get_servers,
)
@patch(
    "prowler.providers.azure.services.mysql.mysql_service.MySQL.__get_configurations__",
    new=mock_mysql_get_configurations,
)
class Test_MySQL_Service:
    def test__get_client__(self):
        mysql = MySQL(set_mocked_azure_provider())
        assert (
            mysql.clients[AZURE_SUBSCRIPTION].__class__.__name__
            == "MySQLManagementClient"
        )

    def test__get_subscriptions__(self):
        mysql = MySQL(set_mocked_azure_provider())
        assert mysql.subscriptions.__class__.__name__ == "dict"

    def test__get_flexible_servers__(self):
        mysql = MySQL(set_mocked_azure_provider())
        assert len(mysql.flexible_servers) == 1
        assert (
            mysql.flexible_servers[AZURE_SUBSCRIPTION]["test"].resource_id
            == "/subscriptions/resource_id"
        )
        assert mysql.flexible_servers[AZURE_SUBSCRIPTION]["test"].location == "location"
        assert mysql.flexible_servers[AZURE_SUBSCRIPTION]["test"].version == "version"
        assert (
            len(mysql.flexible_servers[AZURE_SUBSCRIPTION]["test"].configurations) == 1
        )
        assert (
            mysql.flexible_servers[AZURE_SUBSCRIPTION]["test"]
            .configurations["test"]
            .resource_id
            == "/subscriptions/test/resource_id"
        )
        assert (
            mysql.flexible_servers[AZURE_SUBSCRIPTION]["test"]
            .configurations["test"]
            .description
            == "description"
        )
        assert (
            mysql.flexible_servers[AZURE_SUBSCRIPTION]["test"]
            .configurations["test"]
            .value
            == "value"
        )

    def test__get_configurations__(self):
        mysql = MySQL(set_mocked_azure_provider())
        configurations = mysql.__get_configurations__()

        assert len(configurations) == 1
        assert configurations["test"].resource_id == "/subscriptions/resource_id"
        assert configurations["test"].description == "description"
        assert configurations["test"].value == "value"
