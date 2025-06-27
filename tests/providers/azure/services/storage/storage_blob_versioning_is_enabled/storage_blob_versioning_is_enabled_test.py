from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_storage_blob_versioning_is_enabled:
    def test_storage_no_storage_accounts(self):
        storage_client = mock.MagicMock
        storage_client.storage_accounts = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_blob_versioning_is_enabled.storage_blob_versioning_is_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_blob_versioning_is_enabled.storage_blob_versioning_is_enabled import (
                storage_blob_versioning_is_enabled,
            )

            check = storage_blob_versioning_is_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_storage_no_blob_properties(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        storage_client = mock.MagicMock
        storage_account_blob_properties = None
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_blob_versioning_is_enabled.storage_blob_versioning_is_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_service import Account

            storage_client.storage_accounts = {
                AZURE_SUBSCRIPTION_ID: [
                    Account(
                        id=storage_account_id,
                        name=storage_account_name,
                        resouce_group_name=None,
                        enable_https_traffic_only=False,
                        infrastructure_encryption=False,
                        allow_blob_public_access=None,
                        network_rule_set=None,
                        encryption_type="None",
                        minimum_tls_version=None,
                        key_expiration_period_in_days=None,
                        location="westeurope",
                        private_endpoint_connections=None,
                        blob_properties=storage_account_blob_properties,
                    )
                ]
            }
            from prowler.providers.azure.services.storage.storage_blob_versioning_is_enabled.storage_blob_versioning_is_enabled import (
                storage_blob_versioning_is_enabled,
            )

            check = storage_blob_versioning_is_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_storage_blob_versioning_is_enabled(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        storage_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_blob_versioning_is_enabled.storage_blob_versioning_is_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_service import (
                Account,
                BlobProperties,
                DeleteRetentionPolicy,
            )

            storage_account_blob_properties = BlobProperties(
                id=None,
                name=None,
                type=None,
                default_service_version=None,
                container_delete_retention_policy=DeleteRetentionPolicy(
                    enabled=False, days=0
                ),
                versioning_enabled=True,
            )
            storage_client.storage_accounts = {
                AZURE_SUBSCRIPTION_ID: [
                    Account(
                        id=storage_account_id,
                        name=storage_account_name,
                        resouce_group_name=None,
                        enable_https_traffic_only=False,
                        infrastructure_encryption=False,
                        allow_blob_public_access=None,
                        network_rule_set=None,
                        encryption_type="None",
                        minimum_tls_version=None,
                        key_expiration_period_in_days=None,
                        location="westeurope",
                        private_endpoint_connections=None,
                        blob_properties=storage_account_blob_properties,
                    )
                ]
            }
            from prowler.providers.azure.services.storage.storage_blob_versioning_is_enabled.storage_blob_versioning_is_enabled import (
                storage_blob_versioning_is_enabled,
            )

            check = storage_blob_versioning_is_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_ID} has blob versioning enabled."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id
            assert result[0].location == "westeurope"

    def test_storage_blob_versioning_is_disabled(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        storage_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_blob_versioning_is_enabled.storage_blob_versioning_is_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_service import (
                Account,
                BlobProperties,
                DeleteRetentionPolicy,
            )

            storage_account_blob_properties = BlobProperties(
                id=None,
                name=None,
                type=None,
                default_service_version=None,
                container_delete_retention_policy=DeleteRetentionPolicy(
                    enabled=False, days=0
                ),
                versioning_enabled=False,
            )
            storage_client.storage_accounts = {
                AZURE_SUBSCRIPTION_ID: [
                    Account(
                        id=storage_account_id,
                        name=storage_account_name,
                        resouce_group_name=None,
                        enable_https_traffic_only=False,
                        infrastructure_encryption=False,
                        allow_blob_public_access=None,
                        network_rule_set=None,
                        encryption_type="None",
                        minimum_tls_version=None,
                        key_expiration_period_in_days=None,
                        location="westeurope",
                        private_endpoint_connections=None,
                        blob_properties=storage_account_blob_properties,
                    )
                ]
            }
            from prowler.providers.azure.services.storage.storage_blob_versioning_is_enabled.storage_blob_versioning_is_enabled import (
                storage_blob_versioning_is_enabled,
            )

            check = storage_blob_versioning_is_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_ID} does not have blob versioning enabled."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id
            assert result[0].location == "westeurope"
