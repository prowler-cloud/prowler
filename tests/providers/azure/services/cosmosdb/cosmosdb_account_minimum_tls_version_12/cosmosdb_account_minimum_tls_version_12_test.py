from unittest import mock

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_cosmosdb_account_minimum_tls_version_12:
    def test_no_subscriptions(self):
        cosmosdb_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.cosmosdb.cosmosdb_account_minimum_tls_version_12.cosmosdb_account_minimum_tls_version_12.cosmosdb_client",
                new=cosmosdb_client,
            ),
        ):
            from prowler.providers.azure.services.cosmosdb.cosmosdb_account_minimum_tls_version_12.cosmosdb_account_minimum_tls_version_12 import (
                cosmosdb_account_minimum_tls_version_12,
            )

            cosmosdb_client.accounts = {}

            check = cosmosdb_account_minimum_tls_version_12()
            result = check.execute()
            assert len(result) == 0

    def test_pass(self):
        cosmosdb_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.cosmosdb.cosmosdb_account_minimum_tls_version_12.cosmosdb_account_minimum_tls_version_12.cosmosdb_client",
                new=cosmosdb_client,
            ),
        ):
            from prowler.providers.azure.services.cosmosdb.cosmosdb_account_minimum_tls_version_12.cosmosdb_account_minimum_tls_version_12 import (
                cosmosdb_account_minimum_tls_version_12,
            )
            from prowler.providers.azure.services.cosmosdb.cosmosdb_service import Account

            cosmosdb_client.accounts = {AZURE_SUBSCRIPTION_ID: [Account(
                id="/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.DocumentDB/databaseAccounts/test-account",
                name="test-account",
                kind="GlobalDocumentDB",
                type="Microsoft.DocumentDB/databaseAccounts",
                tags={},
                is_virtual_network_filter_enabled=False,
                location="eastus",
                private_endpoint_connections=[],
                disable_local_auth=False,
                minimal_tls_version="Tls12",
            )]}

            check = cosmosdb_account_minimum_tls_version_12()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_fail(self):
        cosmosdb_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.cosmosdb.cosmosdb_account_minimum_tls_version_12.cosmosdb_account_minimum_tls_version_12.cosmosdb_client",
                new=cosmosdb_client,
            ),
        ):
            from prowler.providers.azure.services.cosmosdb.cosmosdb_account_minimum_tls_version_12.cosmosdb_account_minimum_tls_version_12 import (
                cosmosdb_account_minimum_tls_version_12,
            )
            from prowler.providers.azure.services.cosmosdb.cosmosdb_service import Account

            cosmosdb_client.accounts = {AZURE_SUBSCRIPTION_ID: [Account(
                id="/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.DocumentDB/databaseAccounts/test-account",
                name="test-account",
                kind="GlobalDocumentDB",
                type="Microsoft.DocumentDB/databaseAccounts",
                tags={},
                is_virtual_network_filter_enabled=False,
                location="eastus",
                private_endpoint_connections=[],
                disable_local_auth=False,
                minimal_tls_version="Tls11",
            )]}

            check = cosmosdb_account_minimum_tls_version_12()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
