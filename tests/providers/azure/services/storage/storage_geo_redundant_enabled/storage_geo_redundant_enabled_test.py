from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.storage.storage_service import (
    Account,
    ReplicationSettings,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_storage_geo_redundant_enabled:
    def test_no_storage_accounts(self):
        storage_client = mock.MagicMock()
        storage_client.storage_accounts = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled import (
                storage_geo_redundant_enabled,
            )

            check = storage_geo_redundant_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_storage_geo_redundant_enabled(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account GRS"
        storage_client = mock.MagicMock()
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    resouce_group_name=None,
                    enable_https_traffic_only=False,
                    infrastructure_encryption=False,
                    allow_blob_public_access=False,
                    network_rule_set=None,
                    encryption_type=None,
                    minimum_tls_version=None,
                    key_expiration_period_in_days=None,
                    location="westeurope",
                    private_endpoint_connections=None,
                    replication_settings=ReplicationSettings.STANDARD_GRS,
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled import (
                storage_geo_redundant_enabled,
            )

            check = storage_geo_redundant_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_ID} has Geo-redundant storage (GRS) enabled."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id
            assert result[0].location == "westeurope"

    def test_storage_account_geo_redundant_disabled(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account LRS"
        storage_client = mock.MagicMock()
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    resouce_group_name=None,
                    enable_https_traffic_only=False,
                    infrastructure_encryption=False,
                    allow_blob_public_access=False,
                    network_rule_set=None,
                    encryption_type=None,
                    minimum_tls_version=None,
                    key_expiration_period_in_days=None,
                    location="westeurope",
                    private_endpoint_connections=None,
                    replication_settings=ReplicationSettings.STANDARD_LRS,
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_geo_redundant_enabled.storage_geo_redundant_enabled import (
                storage_geo_redundant_enabled,
            )

            check = storage_geo_redundant_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_ID} does not have Geo-redundant storage (GRS) enabled."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id
            assert result[0].location == "westeurope"
