from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.storage.storage_service import Account, FileShare
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_storage_ensure_file_shares_soft_delete_is_enabled:
    def test_no_storage_accounts(self):
        storage_client = mock.MagicMock
        storage_client.storage_accounts = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_ensure_file_shares_soft_delete_is_enabled.storage_ensure_file_shares_soft_delete_is_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_ensure_file_shares_soft_delete_is_enabled.storage_ensure_file_shares_soft_delete_is_enabled import (
                storage_ensure_file_shares_soft_delete_is_enabled,
            )

            check = storage_ensure_file_shares_soft_delete_is_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_no_file_shares(self):
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
                    network_rule_set=None,
                    encryption_type="None",
                    minimum_tls_version=None,
                    key_expiration_period_in_days=None,
                    location="westeurope",
                    private_endpoint_connections=None,
                    file_shares=[],
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_ensure_file_shares_soft_delete_is_enabled.storage_ensure_file_shares_soft_delete_is_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_ensure_file_shares_soft_delete_is_enabled.storage_ensure_file_shares_soft_delete_is_enabled import (
                storage_ensure_file_shares_soft_delete_is_enabled,
            )

            check = storage_ensure_file_shares_soft_delete_is_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_file_share_soft_delete_disabled(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        file_share = FileShare(
            id="fs1",
            name="share1",
            soft_delete_enabled=False,
            retention_days=0,
        )
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
                    network_rule_set=None,
                    encryption_type="None",
                    minimum_tls_version=None,
                    key_expiration_period_in_days=None,
                    location="westeurope",
                    private_endpoint_connections=None,
                    file_shares=[file_share],
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_ensure_file_shares_soft_delete_is_enabled.storage_ensure_file_shares_soft_delete_is_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_ensure_file_shares_soft_delete_is_enabled.storage_ensure_file_shares_soft_delete_is_enabled import (
                storage_ensure_file_shares_soft_delete_is_enabled,
            )

            check = storage_ensure_file_shares_soft_delete_is_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"File share {file_share.name} in storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_ID} does not have soft delete enabled or has an invalid retention period."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_id == file_share.name
            assert result[0].location == "westeurope"
            assert result[0].resource_name == storage_account_name

    def test_file_share_soft_delete_enabled(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        file_share = FileShare(
            id="fs2",
            name="share2",
            soft_delete_enabled=True,
            retention_days=7,
        )
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
                    network_rule_set=None,
                    encryption_type="None",
                    minimum_tls_version=None,
                    key_expiration_period_in_days=None,
                    location="westeurope",
                    private_endpoint_connections=None,
                    file_shares=[file_share],
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_ensure_file_shares_soft_delete_is_enabled.storage_ensure_file_shares_soft_delete_is_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_ensure_file_shares_soft_delete_is_enabled.storage_ensure_file_shares_soft_delete_is_enabled import (
                storage_ensure_file_shares_soft_delete_is_enabled,
            )

            check = storage_ensure_file_shares_soft_delete_is_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"File share {file_share.name} in storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_ID} has soft delete enabled with a retention period of {file_share.retention_days} days."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_id == file_share.name
            assert result[0].location == "westeurope"
            assert result[0].resource_name == storage_account_name
