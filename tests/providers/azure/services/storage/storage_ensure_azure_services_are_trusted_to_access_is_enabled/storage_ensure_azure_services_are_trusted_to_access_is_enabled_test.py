from unittest import mock
from uuid import uuid4

from azure.mgmt.storage.v2022_09_01.models import NetworkRuleSet

from prowler.providers.azure.services.storage.storage_service import Account
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_storage_ensure_azure_services_are_trusted_to_access_is_enabled:
    def test_storage_no_storage_accounts(self):
        storage_client = mock.MagicMock
        storage_client.storage_accounts = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.storage.storage_ensure_azure_services_are_trusted_to_access_is_enabled.storage_ensure_azure_services_are_trusted_to_access_is_enabled.storage_client",
            new=storage_client,
        ):
            from prowler.providers.azure.services.storage.storage_ensure_azure_services_are_trusted_to_access_is_enabled.storage_ensure_azure_services_are_trusted_to_access_is_enabled import (
                storage_ensure_azure_services_are_trusted_to_access_is_enabled,
            )

            check = storage_ensure_azure_services_are_trusted_to_access_is_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_storage_storage_accounts_azure_services_are_not_trusted_to_access(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        storage_client = mock.MagicMock
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    resouce_group_name=None,
                    enable_https_traffic_only=False,
                    infrastructure_encryption=False,
                    allow_blob_public_access=None,
                    network_rule_set=NetworkRuleSet(bypass=[None]),
                    encryption_type=None,
                    minimum_tls_version=None,
                    key_expiration_period_in_days=None,
                    location="westeurope",
                    private_endpoint_connections=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.storage.storage_ensure_azure_services_are_trusted_to_access_is_enabled.storage_ensure_azure_services_are_trusted_to_access_is_enabled.storage_client",
            new=storage_client,
        ):
            from prowler.providers.azure.services.storage.storage_ensure_azure_services_are_trusted_to_access_is_enabled.storage_ensure_azure_services_are_trusted_to_access_is_enabled import (
                storage_ensure_azure_services_are_trusted_to_access_is_enabled,
            )

            check = storage_ensure_azure_services_are_trusted_to_access_is_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_ID} does not allow trusted Microsoft services to access this storage account."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id
            assert result[0].location == "westeurope"

    def test_storage_storage_accounts_azure_services_are_trusted_to_access(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        storage_client = mock.MagicMock
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    resouce_group_name=None,
                    enable_https_traffic_only=False,
                    infrastructure_encryption=False,
                    allow_blob_public_access=None,
                    network_rule_set=NetworkRuleSet(bypass=["AzureServices"]),
                    encryption_type=None,
                    minimum_tls_version=None,
                    key_expiration_period_in_days=None,
                    location="westeurope",
                    private_endpoint_connections=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.storage.storage_ensure_azure_services_are_trusted_to_access_is_enabled.storage_ensure_azure_services_are_trusted_to_access_is_enabled.storage_client",
            new=storage_client,
        ):
            from prowler.providers.azure.services.storage.storage_ensure_azure_services_are_trusted_to_access_is_enabled.storage_ensure_azure_services_are_trusted_to_access_is_enabled import (
                storage_ensure_azure_services_are_trusted_to_access_is_enabled,
            )

            check = storage_ensure_azure_services_are_trusted_to_access_is_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_ID} allows trusted Microsoft services to access this storage account."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id
            assert result[0].location == "westeurope"
