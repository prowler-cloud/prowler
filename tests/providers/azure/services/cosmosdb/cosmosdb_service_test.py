from unittest.mock import patch

from prowler.providers.azure.services.cosmosdb.cosmosdb_service import Account, CosmosDB
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_audit_info,
)


def mock_cosmosdb_get_accounts(_):
    return {
        AZURE_SUBSCRIPTION: [
            Account(
                id="account_id",
                name="account_name",
                kind=None,
                location=None,
                type=None,
                tags=None,
                is_virtual_network_filter_enabled=None,
                disable_local_auth=None,
            )
        ]
    }


@patch(
    "prowler.providers.azure.services.cosmosdb.cosmosdb_service.CosmosDB.__get_accounts__",
    new=mock_cosmosdb_get_accounts,
)
class Test_CosmosDB_Service:
    def test__get_client__(self):
        account = CosmosDB(set_mocked_azure_audit_info())
        assert (
            account.clients[AZURE_SUBSCRIPTION].__class__.__name__
            == "CosmosDBManagementClient"
        )

    def test__get_accounts__(self):
        account = CosmosDB(set_mocked_azure_audit_info())
        assert account.accounts[AZURE_SUBSCRIPTION][0].__class__.__name__ == "Account"
        assert account.accounts[AZURE_SUBSCRIPTION][0].id == "account_id"
        assert account.accounts[AZURE_SUBSCRIPTION][0].name == "account_name"
        assert account.accounts[AZURE_SUBSCRIPTION][0].kind is None
        assert account.accounts[AZURE_SUBSCRIPTION][0].location is None
        assert account.accounts[AZURE_SUBSCRIPTION][0].type is None
        assert account.accounts[AZURE_SUBSCRIPTION][0].tags is None
        assert (
            account.accounts[AZURE_SUBSCRIPTION][0].is_virtual_network_filter_enabled
            is None
        )
        assert account.accounts[AZURE_SUBSCRIPTION][0].disable_local_auth is None
