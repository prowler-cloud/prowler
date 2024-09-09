from unittest.mock import patch

from prowler.providers.azure.services.mysql.mysql_service import (
    Configuration,
    FlexibleServer,
    MySQL,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


def mock_mysql_get_servers(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
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
    "prowler.providers.azure.services.mysql.mysql_service.MySQL._get_flexible_servers",
    new=mock_mysql_get_servers,
)
@patch(
    "prowler.providers.azure.services.mysql.mysql_service.MySQL._get_configurations",
    new=mock_mysql_get_configurations,
)
class Test_MySQL_Service:
    def test_get_client(self):
        mysql = MySQL(set_mocked_azure_provider())
        assert (
            mysql.clients[AZURE_SUBSCRIPTION_ID].__class__.__name__
            == "MySQLManagementClient"
        )

    def test__get_subscriptions__(self):
        mysql = MySQL(set_mocked_azure_provider())
        assert mysql.subscriptions.__class__.__name__ == "dict"

    def test_get_flexible_servers(self):
        mysql = MySQL(set_mocked_azure_provider())
        assert len(mysql.flexible_servers) == 1
        assert (
            mysql.flexible_servers[AZURE_SUBSCRIPTION_ID]["test"].resource_id
            == "/subscriptions/resource_id"
        )
        assert (
            mysql.flexible_servers[AZURE_SUBSCRIPTION_ID]["test"].location == "location"
        )
        assert (
            mysql.flexible_servers[AZURE_SUBSCRIPTION_ID]["test"].version == "version"
        )
        assert (
            len(mysql.flexible_servers[AZURE_SUBSCRIPTION_ID]["test"].configurations)
            == 1
        )
        assert (
            mysql.flexible_servers[AZURE_SUBSCRIPTION_ID]["test"]
            .configurations["test"]
            .resource_id
            == "/subscriptions/test/resource_id"
        )
        assert (
            mysql.flexible_servers[AZURE_SUBSCRIPTION_ID]["test"]
            .configurations["test"]
            .description
            == "description"
        )
        assert (
            mysql.flexible_servers[AZURE_SUBSCRIPTION_ID]["test"]
            .configurations["test"]
            .value
            == "value"
        )

    def test_get_configurations(self):
        mysql = MySQL(set_mocked_azure_provider())
        configurations = mysql._get_configurations()

        assert len(configurations) == 1
        assert configurations["test"].resource_id == "/subscriptions/resource_id"
        assert configurations["test"].description == "description"
        assert configurations["test"].value == "value"
