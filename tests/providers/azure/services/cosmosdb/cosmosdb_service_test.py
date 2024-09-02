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
