from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.cosmosdb.cosmosdb_service import Account
from tests.providers.azure.azure_fixtures import AZURE_SUBSCRIPTION


class Test_cosmosdb_account_firewall_use_selected_networks:
    def test_no_accounts(self):
        cosmosdb_client = mock.MagicMock
        cosmosdb_client.accounts = {}

        with mock.patch(
            "prowler.providers.azure.services.cosmosdb.cosmosdb_account_firewall_use_selected_networks.cosmosdb_account_firewall_use_selected_networks.cosmosdb_client",
            new=cosmosdb_client,
        ):
            from prowler.providers.azure.services.cosmosdb.cosmosdb_account_firewall_use_selected_networks.cosmosdb_account_firewall_use_selected_networks import (
                cosmosdb_account_firewall_use_selected_networks,
            )

            check = cosmosdb_account_firewall_use_selected_networks()
            result = check.execute()
            assert len(result) == 0

    def test_accounts_no_virtual_network_filter_enabled(self):
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
                    disable_local_auth=None,
                    is_virtual_network_filter_enabled=False,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.cosmosdb.cosmosdb_account_firewall_use_selected_networks.cosmosdb_account_firewall_use_selected_networks.cosmosdb_client",
            new=cosmosdb_client,
        ):
            from prowler.providers.azure.services.cosmosdb.cosmosdb_account_firewall_use_selected_networks.cosmosdb_account_firewall_use_selected_networks import (
                cosmosdb_account_firewall_use_selected_networks,
            )

            check = cosmosdb_account_firewall_use_selected_networks()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CosmosDB account {account_name} from subscription {AZURE_SUBSCRIPTION} has firewall rules that allow access from all networks."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == account_name
            assert result[0].resource_id == account_id

    def test_accounts_virtual_network_filter_enabled(self):
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
                    disable_local_auth=None,
                    is_virtual_network_filter_enabled=True,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.cosmosdb.cosmosdb_account_firewall_use_selected_networks.cosmosdb_account_firewall_use_selected_networks.cosmosdb_client",
            new=cosmosdb_client,
        ):
            from prowler.providers.azure.services.cosmosdb.cosmosdb_account_firewall_use_selected_networks.cosmosdb_account_firewall_use_selected_networks import (
                cosmosdb_account_firewall_use_selected_networks,
            )

            check = cosmosdb_account_firewall_use_selected_networks()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CosmosDB account {account_name} from subscription {AZURE_SUBSCRIPTION} has firewall rules that allow access only from selected networks."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == account_name
            assert result[0].resource_id == account_id
