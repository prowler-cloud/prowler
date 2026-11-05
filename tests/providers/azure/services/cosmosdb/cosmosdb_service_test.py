from unittest.mock import MagicMock, patch

from prowler.providers.azure.services.cosmosdb.cosmosdb_service import Account, CosmosDB
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    RESOURCE_GROUP,
    RESOURCE_GROUP_LIST,
    set_mocked_azure_provider,
)


def mock_cosmosdb_get_accounts(_):
    return {
        AZURE_SUBSCRIPTION_ID: [
            Account(
                id="account_id",
                name="account_name",
                kind=None,
                location="westeu",
                type=None,
                tags=None,
                is_virtual_network_filter_enabled=None,
                disable_local_auth=None,
                private_endpoint_connections=[],
            )
        ]
    }


@patch(
    "prowler.providers.azure.services.cosmosdb.cosmosdb_service.CosmosDB._get_accounts",
    new=mock_cosmosdb_get_accounts,
)
class Test_CosmosDB_Service:
    def test_get_client(self):
        account = CosmosDB(set_mocked_azure_provider())
        assert (
            account.clients[AZURE_SUBSCRIPTION_ID].__class__.__name__
            == "CosmosDBManagementClient"
        )

    def test_get_accounts(self):
        account = CosmosDB(set_mocked_azure_provider())
        assert (
            account.accounts[AZURE_SUBSCRIPTION_ID][0].__class__.__name__ == "Account"
        )
        assert account.accounts[AZURE_SUBSCRIPTION_ID][0].id == "account_id"
        assert account.accounts[AZURE_SUBSCRIPTION_ID][0].name == "account_name"
        assert account.accounts[AZURE_SUBSCRIPTION_ID][0].kind is None
        assert account.accounts[AZURE_SUBSCRIPTION_ID][0].location == "westeu"
        assert account.accounts[AZURE_SUBSCRIPTION_ID][0].type is None
        assert account.accounts[AZURE_SUBSCRIPTION_ID][0].tags is None
        assert (
            account.accounts[AZURE_SUBSCRIPTION_ID][0].is_virtual_network_filter_enabled
            is None
        )
        assert account.accounts[AZURE_SUBSCRIPTION_ID][0].disable_local_auth is None


def mock_cosmosdb_get_accounts_with_none(_):
    """Mock CosmosDB accounts with None private_endpoint_connections"""
    from prowler.providers.azure.services.cosmosdb.cosmosdb_service import (
        PrivateEndpointConnection,
    )

    return {
        AZURE_SUBSCRIPTION_ID: [
            Account(
                id="/subscriptions/test/account1",
                name="cosmosdb-none-pec",
                kind="GlobalDocumentDB",
                location="eastus",
                type="Microsoft.DocumentDB/databaseAccounts",
                tags={},
                is_virtual_network_filter_enabled=False,
                disable_local_auth=False,
                private_endpoint_connections=[],  # Empty list from getattr default
            ),
            Account(
                id="/subscriptions/test/account2",
                name="cosmosdb-with-pec",
                kind="MongoDB",
                location="westus",
                type="Microsoft.DocumentDB/databaseAccounts",
                tags={"env": "test"},
                is_virtual_network_filter_enabled=True,
                disable_local_auth=True,
                private_endpoint_connections=[
                    PrivateEndpointConnection(
                        id="/subscriptions/test/pec1",
                        name="pec-1",
                        type="Microsoft.Network/privateEndpoints",
                    )
                ],
            ),
        ]
    }


@patch(
    "prowler.providers.azure.services.cosmosdb.cosmosdb_service.CosmosDB._get_accounts",
    new=mock_cosmosdb_get_accounts_with_none,
)
class Test_CosmosDB_Service_None_Handling:
    """Test CosmosDB service handling of None values"""

    def test_account_with_none_private_endpoint_connections(self):
        """Test that CosmosDB handles None private_endpoint_connections gracefully"""
        cosmosdb = CosmosDB(set_mocked_azure_provider())

        # Find account with no connections
        account = next(
            acc
            for acc in cosmosdb.accounts[AZURE_SUBSCRIPTION_ID]
            if acc.name == "cosmosdb-none-pec"
        )
        assert account.private_endpoint_connections == []
        assert account.disable_local_auth is False

    def test_account_with_valid_private_endpoint_connections(self):
        """Test that CosmosDB handles valid private_endpoint_connections"""
        cosmosdb = CosmosDB(set_mocked_azure_provider())

        # Find account with connections
        account = next(
            acc
            for acc in cosmosdb.accounts[AZURE_SUBSCRIPTION_ID]
            if acc.name == "cosmosdb-with-pec"
        )
        assert len(account.private_endpoint_connections) == 1
        assert account.private_endpoint_connections[0].id == "/subscriptions/test/pec1"
        assert account.private_endpoint_connections[0].name == "pec-1"
        assert (
            account.private_endpoint_connections[0].type
            == "Microsoft.Network/privateEndpoints"
        )
        assert account.disable_local_auth is True


class Test_CosmosDB_get_accounts:
    def test_get_accounts_no_resource_groups(self):
        mock_client = MagicMock()
        mock_client.database_accounts.list.return_value = []

        with patch(
            "prowler.providers.azure.services.cosmosdb.cosmosdb_service.CosmosDB._get_accounts",
            return_value={},
        ):
            cosmosdb = CosmosDB(set_mocked_azure_provider())

        cosmosdb.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        cosmosdb.resource_groups = None

        result = cosmosdb._get_accounts()

        mock_client.database_accounts.list.assert_called_once()
        mock_client.database_accounts.list_by_resource_group.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_accounts_with_resource_group(self):
        mock_account = MagicMock()
        mock_account.id = "account-id"
        mock_account.name = "my-cosmos"
        mock_account.kind = "GlobalDocumentDB"
        mock_account.location = "eastus"
        mock_account.type = "Microsoft.DocumentDB/databaseAccounts"
        mock_account.tags = {}
        mock_account.is_virtual_network_filter_enabled = False
        mock_account.private_endpoint_connections = []
        mock_account.disable_local_auth = False

        mock_client = MagicMock()
        mock_client.database_accounts.list_by_resource_group.return_value = [
            mock_account
        ]

        with patch(
            "prowler.providers.azure.services.cosmosdb.cosmosdb_service.CosmosDB._get_accounts",
            return_value={},
        ):
            cosmosdb = CosmosDB(set_mocked_azure_provider())

        cosmosdb.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        cosmosdb.resource_groups = {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}

        result = cosmosdb._get_accounts()

        mock_client.database_accounts.list_by_resource_group.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP
        )
        mock_client.database_accounts.list.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result
        assert len(result[AZURE_SUBSCRIPTION_ID]) == 1

    def test_get_accounts_empty_resource_group_for_subscription(self):
        mock_client = MagicMock()

        with patch(
            "prowler.providers.azure.services.cosmosdb.cosmosdb_service.CosmosDB._get_accounts",
            return_value={},
        ):
            cosmosdb = CosmosDB(set_mocked_azure_provider())

        cosmosdb.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        cosmosdb.resource_groups = {AZURE_SUBSCRIPTION_ID: []}

        result = cosmosdb._get_accounts()

        mock_client.database_accounts.list_by_resource_group.assert_not_called()
        mock_client.database_accounts.list.assert_not_called()
        assert result[AZURE_SUBSCRIPTION_ID] == []

    def test_get_accounts_with_multiple_resource_groups(self):
        mock_client = MagicMock()
        mock_client.database_accounts.list_by_resource_group.return_value = []

        with patch(
            "prowler.providers.azure.services.cosmosdb.cosmosdb_service.CosmosDB._get_accounts",
            return_value={},
        ):
            cosmosdb = CosmosDB(set_mocked_azure_provider())

        cosmosdb.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        cosmosdb.resource_groups = {AZURE_SUBSCRIPTION_ID: RESOURCE_GROUP_LIST}

        result = cosmosdb._get_accounts()

        assert mock_client.database_accounts.list_by_resource_group.call_count == 2
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_accounts_with_mixed_case_resource_group(self):
        mock_client = MagicMock()
        mock_client.database_accounts.list_by_resource_group.return_value = []

        with patch(
            "prowler.providers.azure.services.cosmosdb.cosmosdb_service.CosmosDB._get_accounts",
            return_value={},
        ):
            cosmosdb = CosmosDB(set_mocked_azure_provider())

        cosmosdb.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        cosmosdb.resource_groups = {AZURE_SUBSCRIPTION_ID: ["RG"]}

        cosmosdb._get_accounts()

        mock_client.database_accounts.list_by_resource_group.assert_called_once_with(
            resource_group_name="RG"
        )
