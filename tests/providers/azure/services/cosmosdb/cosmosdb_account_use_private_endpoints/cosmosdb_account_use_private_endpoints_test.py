from unittest import mock
from uuid import uuid4

from azure.mgmt.cosmosdb.models import PrivateEndpointConnection

from prowler.providers.azure.services.cosmosdb.cosmosdb_service import Account
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_cosmosdb_account_use_private_endpoints:
    def test_no_accounts(self):
        cosmosdb_client = mock.MagicMock
        cosmosdb_client.accounts = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.cosmosdb.cosmosdb_account_use_private_endpoints.cosmosdb_account_use_private_endpoints.cosmosdb_client",
            new=cosmosdb_client,
        ):
            from prowler.providers.azure.services.cosmosdb.cosmosdb_account_use_private_endpoints.cosmosdb_account_use_private_endpoints import (
                cosmosdb_account_use_private_endpoints,
            )

            check = cosmosdb_account_use_private_endpoints()
            result = check.execute()
            assert len(result) == 0

    def test_accounts_no_private_endpoints_connections(self):
        cosmosdb_client = mock.MagicMock
        account_name = "Account Name"
        account_id = str(uuid4())
        cosmosdb_client.accounts = {
            AZURE_SUBSCRIPTION_ID: [
                Account(
                    id=account_id,
                    name=account_name,
                    kind=None,
                    location="westeu",
                    type=None,
                    tags=None,
                    is_virtual_network_filter_enabled=None,
                    private_endpoint_connections=None,
                    disable_local_auth=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.cosmosdb.cosmosdb_account_use_private_endpoints.cosmosdb_account_use_private_endpoints.cosmosdb_client",
            new=cosmosdb_client,
        ):
            from prowler.providers.azure.services.cosmosdb.cosmosdb_account_use_private_endpoints.cosmosdb_account_use_private_endpoints import (
                cosmosdb_account_use_private_endpoints,
            )

            check = cosmosdb_account_use_private_endpoints()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CosmosDB account {account_name} from subscription {AZURE_SUBSCRIPTION_ID} is not using private endpoints connections"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == account_name
            assert result[0].resource_id == account_id
            assert result[0].location == "westeu"

    def test_accounts_private_endpoints_connections(self):
        cosmosdb_client = mock.MagicMock
        account_name = "Account Name"
        account_id = str(uuid4())
        cosmosdb_client.accounts = {
            AZURE_SUBSCRIPTION_ID: [
                Account(
                    id=account_id,
                    name=account_name,
                    kind=None,
                    location="westeu",
                    type=None,
                    tags=None,
                    is_virtual_network_filter_enabled=None,
                    private_endpoint_connections=[
                        PrivateEndpointConnection(
                            id="private_endpoint", name="private_name"
                        )
                    ],
                    disable_local_auth=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.cosmosdb.cosmosdb_account_use_private_endpoints.cosmosdb_account_use_private_endpoints.cosmosdb_client",
            new=cosmosdb_client,
        ):
            from prowler.providers.azure.services.cosmosdb.cosmosdb_account_use_private_endpoints.cosmosdb_account_use_private_endpoints import (
                cosmosdb_account_use_private_endpoints,
            )

            check = cosmosdb_account_use_private_endpoints()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CosmosDB account {account_name} from subscription {AZURE_SUBSCRIPTION_ID} is using private endpoints connections"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == account_name
            assert result[0].resource_id == account_id
            assert result[0].location == "westeu"
