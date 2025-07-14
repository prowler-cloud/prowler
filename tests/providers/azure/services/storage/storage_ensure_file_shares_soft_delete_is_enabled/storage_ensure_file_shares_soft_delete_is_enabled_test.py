from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.storage.storage_service import (
    Account,
    DeleteRetentionPolicy,
    FileServiceProperties,
    NetworkRuleSet,
    SMBProtocolSettings,
)
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

    def test_storage_account_no_file_properties(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        storage_client = mock.MagicMock
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    resouce_group_name="rg",
                    enable_https_traffic_only=False,
                    infrastructure_encryption=False,
                    allow_blob_public_access=False,
                    network_rule_set=NetworkRuleSet(
                        bypass="AzureServices", default_action="Allow"
                    ),
                    encryption_type="None",
                    minimum_tls_version="TLS1_2",
                    key_expiration_period_in_days=None,
                    location="westeurope",
                    private_endpoint_connections=[],
                    file_service_properties=None,
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
        storage_client = mock.MagicMock
        retention_policy = DeleteRetentionPolicy(enabled=False, days=0)
        file_service_properties = FileServiceProperties(
            id=f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/prowler-resource-group/providers/Microsoft.Storage/storageAccounts/{storage_account_name}/fileServices/default",
            name="default",
            type="Microsoft.Storage/storageAccounts/fileServices",
            share_delete_retention_policy=retention_policy,
            smb_protocol_settings=SMBProtocolSettings(
                channel_encryption=[], supported_versions=[]
            ),
        )
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    resouce_group_name="rg",
                    enable_https_traffic_only=False,
                    infrastructure_encryption=False,
                    allow_blob_public_access=False,
                    network_rule_set=NetworkRuleSet(
                        bypass="AzureServices", default_action="Allow"
                    ),
                    encryption_type="None",
                    minimum_tls_version="TLS1_2",
                    key_expiration_period_in_days=None,
                    location="westeurope",
                    private_endpoint_connections=[],
                    file_service_properties=file_service_properties,
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
                == f"File share soft delete is not enabled for storage account {storage_account_name}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == file_service_properties.id
            assert result[0].location == "westeurope"

    def test_file_share_soft_delete_enabled(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        storage_client = mock.MagicMock
        retention_policy = DeleteRetentionPolicy(enabled=True, days=7)
        file_service_properties = FileServiceProperties(
            id=f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/prowler-resource-group/providers/Microsoft.Storage/storageAccounts/{storage_account_name}/fileServices/default",
            name="default",
            type="Microsoft.Storage/storageAccounts/fileServices",
            share_delete_retention_policy=retention_policy,
            smb_protocol_settings=SMBProtocolSettings(
                channel_encryption=[], supported_versions=[]
            ),
        )
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    resouce_group_name="rg",
                    enable_https_traffic_only=False,
                    infrastructure_encryption=False,
                    allow_blob_public_access=False,
                    network_rule_set=NetworkRuleSet(
                        bypass="AzureServices", default_action="Allow"
                    ),
                    encryption_type="None",
                    minimum_tls_version="TLS1_2",
                    key_expiration_period_in_days=None,
                    location="westeurope",
                    private_endpoint_connections=[],
                    file_service_properties=file_service_properties,
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
                == f"File share soft delete is enabled for storage account {storage_account_name} with a retention period of {retention_policy.days} days."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == file_service_properties.id
            assert result[0].location == "westeurope"
