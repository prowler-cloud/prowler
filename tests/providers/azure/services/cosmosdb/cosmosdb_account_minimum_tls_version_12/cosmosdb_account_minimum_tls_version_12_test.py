from unittest import mock

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_cosmosdb_account_minimum_tls_version_12:
    def test_no_subscriptions(self):
        cosmosdb_client = mock.MagicMock()

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

    def test_pass_tls12(self):
        cosmosdb_client = mock.MagicMock()

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
            from prowler.providers.azure.services.cosmosdb.cosmosdb_service import (
                Account,
            )

            cosmosdb_client.accounts = {
                AZURE_SUBSCRIPTION_ID: [
                    Account(
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
                    )
                ]
            }

            check = cosmosdb_account_minimum_tls_version_12()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"CosmosDB account test-account from subscription "
                f"{AZURE_SUBSCRIPTION_ID} enforces TLS 1.2 or higher."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_pass_tls13(self):
        cosmosdb_client = mock.MagicMock()

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
            from prowler.providers.azure.services.cosmosdb.cosmosdb_service import (
                Account,
            )

            cosmosdb_client.accounts = {
                AZURE_SUBSCRIPTION_ID: [
                    Account(
                        id="/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.DocumentDB/databaseAccounts/test-account",
                        name="test-account",
                        kind="GlobalDocumentDB",
                        type="Microsoft.DocumentDB/databaseAccounts",
                        tags={},
                        is_virtual_network_filter_enabled=False,
                        location="eastus",
                        private_endpoint_connections=[],
                        disable_local_auth=False,
                        minimal_tls_version="Tls13",
                    )
                ]
            }

            check = cosmosdb_account_minimum_tls_version_12()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_fail_tls11(self):
        cosmosdb_client = mock.MagicMock()

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
            from prowler.providers.azure.services.cosmosdb.cosmosdb_service import (
                Account,
            )

            cosmosdb_client.accounts = {
                AZURE_SUBSCRIPTION_ID: [
                    Account(
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
                    )
                ]
            }

            check = cosmosdb_account_minimum_tls_version_12()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"CosmosDB account test-account from subscription "
                f"{AZURE_SUBSCRIPTION_ID} does not enforce TLS 1.2 or higher."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_fail_no_tls_version(self):
        cosmosdb_client = mock.MagicMock()

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
            from prowler.providers.azure.services.cosmosdb.cosmosdb_service import (
                Account,
            )

            cosmosdb_client.accounts = {
                AZURE_SUBSCRIPTION_ID: [
                    Account(
                        id="/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.DocumentDB/databaseAccounts/test-account",
                        name="test-account",
                        kind="GlobalDocumentDB",
                        type="Microsoft.DocumentDB/databaseAccounts",
                        tags={},
                        is_virtual_network_filter_enabled=False,
                        location="eastus",
                        private_endpoint_connections=[],
                        disable_local_auth=False,
                        minimal_tls_version=None,
                    )
                ]
            }

            check = cosmosdb_account_minimum_tls_version_12()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
