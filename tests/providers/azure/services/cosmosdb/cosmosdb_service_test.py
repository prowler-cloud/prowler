from unittest.mock import patch

from prowler.providers.azure.services.cosmosdb.cosmosdb_service import Account, CosmosDB
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
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
