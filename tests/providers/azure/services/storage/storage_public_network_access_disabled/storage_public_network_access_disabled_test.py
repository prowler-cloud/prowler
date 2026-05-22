from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.storage.storage_service import (
    Account,
    NetworkRuleSet,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)


class Test_storage_public_network_access_disabled:
    def test_no_storage_accounts(self):
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_public_network_access_disabled.storage_public_network_access_disabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_public_network_access_disabled.storage_public_network_access_disabled import (
                storage_public_network_access_disabled,
            )

            check = storage_public_network_access_disabled()
            result = check.execute()
            assert len(result) == 0

    def _account(self, name, public_network_access):
        return Account(
            id=str(uuid4()),
            name=name,
            resouce_group_name="rg",
            enable_https_traffic_only=False,
            infrastructure_encryption=False,
            allow_blob_public_access=False,
            public_network_access=public_network_access,
            network_rule_set=NetworkRuleSet(
                bypass="AzureServices", default_action="Allow"
            ),
            encryption_type="None",
            minimum_tls_version="TLS1_2",
            private_endpoint_connections=[],
            key_expiration_period_in_days=None,
            location="westeurope",
        )

    def test_public_network_access_disabled(self):
        storage_account_name = "Test Storage Account"
        account = self._account(storage_account_name, "Disabled")
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {AZURE_SUBSCRIPTION_ID: [account]}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_public_network_access_disabled.storage_public_network_access_disabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_public_network_access_disabled.storage_public_network_access_disabled import (
                storage_public_network_access_disabled,
            )

            check = storage_public_network_access_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} has public network access disabled."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == account.id

    def test_public_network_access_enabled(self):
        storage_account_name = "Test Storage Account"
        account = self._account(storage_account_name, "Enabled")
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {AZURE_SUBSCRIPTION_ID: [account]}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_public_network_access_disabled.storage_public_network_access_disabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_public_network_access_disabled.storage_public_network_access_disabled import (
                storage_public_network_access_disabled,
            )

            check = storage_public_network_access_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} has public network access enabled."
            )

    def test_public_network_access_unset_fails(self):
        storage_account_name = "Test Storage Account"
        account = self._account(storage_account_name, None)
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {AZURE_SUBSCRIPTION_ID: [account]}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_public_network_access_disabled.storage_public_network_access_disabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_public_network_access_disabled.storage_public_network_access_disabled import (
                storage_public_network_access_disabled,
            )

            check = storage_public_network_access_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} has public network access enabled."
            )
