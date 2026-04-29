from unittest.mock import MagicMock, patch

from prowler.providers.azure.services.mysql.mysql_service import (
    Configuration,
    FlexibleServer,
    MySQL,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    RESOURCE_GROUP,
    RESOURCE_GROUP_LIST,
    set_mocked_azure_provider,
)


def mock_mysql_get_servers(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
            "/subscriptions/resource_id": FlexibleServer(
                resource_id="/subscriptions/resource_id",
                name="test",
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
            mysql.flexible_servers[AZURE_SUBSCRIPTION_ID][
                "/subscriptions/resource_id"
            ].resource_id
            == "/subscriptions/resource_id"
        )
        assert (
            mysql.flexible_servers[AZURE_SUBSCRIPTION_ID][
                "/subscriptions/resource_id"
            ].location
            == "location"
        )
        assert (
            mysql.flexible_servers[AZURE_SUBSCRIPTION_ID][
                "/subscriptions/resource_id"
            ].version
            == "version"
        )
        assert (
            len(
                mysql.flexible_servers[AZURE_SUBSCRIPTION_ID][
                    "/subscriptions/resource_id"
                ].configurations
            )
            == 1
        )
        assert (
            mysql.flexible_servers[AZURE_SUBSCRIPTION_ID]["/subscriptions/resource_id"]
            .configurations["test"]
            .resource_id
            == "/subscriptions/test/resource_id"
        )
        assert (
            mysql.flexible_servers[AZURE_SUBSCRIPTION_ID]["/subscriptions/resource_id"]
            .configurations["test"]
            .description
            == "description"
        )
        assert (
            mysql.flexible_servers[AZURE_SUBSCRIPTION_ID]["/subscriptions/resource_id"]
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


class Test_MySQL_get_flexible_servers:
    def test_get_flexible_servers_no_resource_groups(self):
        mock_client = MagicMock()
        mock_client.servers.list.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.mysql.mysql_service.MySQL._get_flexible_servers",
                return_value={},
            ),
            patch(
                "prowler.providers.azure.services.mysql.mysql_service.MySQL._get_configurations",
                return_value={},
            ),
        ):
            mysql = MySQL(set_mocked_azure_provider())

        mysql.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        mysql.resource_groups = None

        result = mysql._get_flexible_servers()

        mock_client.servers.list.assert_called_once()
        mock_client.servers.list_by_resource_group.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_flexible_servers_with_resource_group(self):
        mock_client = MagicMock()
        mock_client.servers.list_by_resource_group.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.mysql.mysql_service.MySQL._get_flexible_servers",
                return_value={},
            ),
            patch(
                "prowler.providers.azure.services.mysql.mysql_service.MySQL._get_configurations",
                return_value={},
            ),
        ):
            mysql = MySQL(set_mocked_azure_provider())

        mysql.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        mysql.resource_groups = {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}

        result = mysql._get_flexible_servers()

        # MySQL uses positional arg, not keyword
        mock_client.servers.list_by_resource_group.assert_called_once_with(
            RESOURCE_GROUP
        )
        mock_client.servers.list.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_flexible_servers_empty_resource_group_for_subscription(self):
        mock_client = MagicMock()

        with (
            patch(
                "prowler.providers.azure.services.mysql.mysql_service.MySQL._get_flexible_servers",
                return_value={},
            ),
            patch(
                "prowler.providers.azure.services.mysql.mysql_service.MySQL._get_configurations",
                return_value={},
            ),
        ):
            mysql = MySQL(set_mocked_azure_provider())

        mysql.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        mysql.resource_groups = {AZURE_SUBSCRIPTION_ID: []}

        result = mysql._get_flexible_servers()

        mock_client.servers.list_by_resource_group.assert_not_called()
        mock_client.servers.list.assert_not_called()
        # MySQL uses `continue` when empty RGs, so the subscription key is not added
        assert AZURE_SUBSCRIPTION_ID not in result

    def test_get_flexible_servers_with_multiple_resource_groups(self):
        mock_client = MagicMock()
        mock_client.servers.list_by_resource_group.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.mysql.mysql_service.MySQL._get_flexible_servers",
                return_value={},
            ),
            patch(
                "prowler.providers.azure.services.mysql.mysql_service.MySQL._get_configurations",
                return_value={},
            ),
        ):
            mysql = MySQL(set_mocked_azure_provider())

        mysql.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        mysql.resource_groups = {AZURE_SUBSCRIPTION_ID: RESOURCE_GROUP_LIST}

        result = mysql._get_flexible_servers()

        assert mock_client.servers.list_by_resource_group.call_count == 2
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_flexible_servers_with_mixed_case_resource_group(self):
        mock_client = MagicMock()
        mock_client.servers.list_by_resource_group.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.mysql.mysql_service.MySQL._get_flexible_servers",
                return_value={},
            ),
            patch(
                "prowler.providers.azure.services.mysql.mysql_service.MySQL._get_configurations",
                return_value={},
            ),
        ):
            mysql = MySQL(set_mocked_azure_provider())

        mysql.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        mysql.resource_groups = {AZURE_SUBSCRIPTION_ID: ["RG"]}

        mysql._get_flexible_servers()

        # MySQL uses positional arg, not keyword
        mock_client.servers.list_by_resource_group.assert_called_once_with("RG")
