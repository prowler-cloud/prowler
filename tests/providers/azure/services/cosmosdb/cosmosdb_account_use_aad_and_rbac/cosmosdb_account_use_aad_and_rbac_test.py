from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.cosmosdb.cosmosdb_service import Account

AZURE_SUBSCRIPTION = str(uuid4())


class Test_cosmosdb_account_use_aad_and_rbac:
    def test_no_accounts(self):
        cosmosdb_client = mock.MagicMock
        cosmosdb_client.accounts = {}

        with mock.patch(
            "prowler.providers.azure.services.cosmosdb.cosmosdb_account_use_aad_and_rbac.cosmosdb_account_use_aad_and_rbac.cosmosdb_client",
            new=cosmosdb_client,
        ):
            from prowler.providers.azure.services.cosmosdb.cosmosdb_account_use_aad_and_rbac.cosmosdb_account_use_aad_and_rbac import (
                cosmosdb_account_use_aad_and_rbac,
            )

            check = cosmosdb_account_use_aad_and_rbac()
            result = check.execute()
            assert len(result) == 0

    def test_accounts_disable_local_auth_false(self):
        cosmosdb_client = mock.MagicMock
        account_name = "Account Name"
        account_id = str(uuid4())
        cosmosdb_client.accounts = {
            AZURE_SUBSCRIPTION: [
                Account(
                    id=account_id,
                    name=account_name,
                    kind=None,
                    location=None,
                    type=None,
                    tags=None,
                    is_virtual_network_filter_enabled=None,
                    private_endpoint_connections=None,
                    disable_local_auth=False,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.cosmosdb.cosmosdb_account_use_aad_and_rbac.cosmosdb_account_use_aad_and_rbac.cosmosdb_client",
            new=cosmosdb_client,
        ):
            from prowler.providers.azure.services.cosmosdb.cosmosdb_account_use_aad_and_rbac.cosmosdb_account_use_aad_and_rbac import (
                cosmosdb_account_use_aad_and_rbac,
            )

            check = cosmosdb_account_use_aad_and_rbac()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CosmosDB account {account_name} from subscription {AZURE_SUBSCRIPTION} is not using AAD and RBAC"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == account_name
            assert result[0].resource_id == account_id

    def test_accounts_disable_local_auth_true(self):
        cosmosdb_client = mock.MagicMock
        account_name = "Account Name"
        account_id = str(uuid4())
        cosmosdb_client.accounts = {
            AZURE_SUBSCRIPTION: [
                Account(
                    id=account_id,
                    name=account_name,
                    kind=None,
                    location=None,
                    type=None,
                    tags=None,
                    is_virtual_network_filter_enabled=None,
                    private_endpoint_connections=None,
                    disable_local_auth=True,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.cosmosdb.cosmosdb_account_use_aad_and_rbac.cosmosdb_account_use_aad_and_rbac.cosmosdb_client",
            new=cosmosdb_client,
        ):
            from prowler.providers.azure.services.cosmosdb.cosmosdb_account_use_aad_and_rbac.cosmosdb_account_use_aad_and_rbac import (
                cosmosdb_account_use_aad_and_rbac,
            )

            check = cosmosdb_account_use_aad_and_rbac()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CosmosDB account {account_name} from subscription {AZURE_SUBSCRIPTION} is using AAD and RBAC"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == account_name
            assert result[0].resource_id == account_id
