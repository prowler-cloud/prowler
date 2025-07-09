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


class Test_storage_smb_protocol_version_is_latest:
    def test_no_storage_accounts(self):
        storage_client = mock.MagicMock()
        storage_client.storage_accounts = {}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_smb_protocol_version_is_latest.storage_smb_protocol_version_is_latest.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_smb_protocol_version_is_latest.storage_smb_protocol_version_is_latest import (
                storage_smb_protocol_version_is_latest,
            )

            check = storage_smb_protocol_version_is_latest()
            result = check.execute()
            assert len(result) == 0

    def test_no_file_service_properties(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        storage_client = mock.MagicMock()
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    resouce_group_name="rg",
                    enable_https_traffic_only=True,
                    infrastructure_encryption=True,
                    allow_blob_public_access=False,
                    network_rule_set=NetworkRuleSet(
                        bypass="AzureServices", default_action="Allow"
                    ),
                    encryption_type="type",
                    minimum_tls_version="TLS1_2",
                    private_endpoint_connections=[],
                    key_expiration_period_in_days=None,
                    location="eastus",
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
                "prowler.providers.azure.services.storage.storage_smb_protocol_version_is_latest.storage_smb_protocol_version_is_latest.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_smb_protocol_version_is_latest.storage_smb_protocol_version_is_latest import (
                storage_smb_protocol_version_is_latest,
            )

            check = storage_smb_protocol_version_is_latest()
            result = check.execute()
            assert len(result) == 0

    def test_only_latest_smb_protocol_version(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        file_service_properties = FileServiceProperties(
            id=storage_account_id,
            name="default",
            type="type",
            share_delete_retention_policy=DeleteRetentionPolicy(enabled=True, days=7),
            smb_protocol_settings=SMBProtocolSettings(
                channel_encryption=[], supported_versions=["SMB3.1.1"]
            ),
        )
        storage_client = mock.MagicMock()
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    resouce_group_name="rg",
                    enable_https_traffic_only=True,
                    infrastructure_encryption=True,
                    allow_blob_public_access=False,
                    network_rule_set=NetworkRuleSet(
                        bypass="AzureServices", default_action="Allow"
                    ),
                    encryption_type="type",
                    minimum_tls_version="TLS1_2",
                    private_endpoint_connections=[],
                    key_expiration_period_in_days=None,
                    location="eastus",
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
                "prowler.providers.azure.services.storage.storage_smb_protocol_version_is_latest.storage_smb_protocol_version_is_latest.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_smb_protocol_version_is_latest.storage_smb_protocol_version_is_latest import (
                storage_smb_protocol_version_is_latest,
            )

            check = storage_smb_protocol_version_is_latest()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_ID} allows only the latest SMB protocol version (SMB3.1.1) for file shares."
                in result[0].status_extended
            )

    def test_multiple_smb_protocol_versions(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        file_service_properties = FileServiceProperties(
            id=storage_account_id,
            name="default",
            type="type",
            share_delete_retention_policy=DeleteRetentionPolicy(enabled=True, days=7),
            smb_protocol_settings=SMBProtocolSettings(
                channel_encryption=[], supported_versions=["SMB2.1", "SMB3.1.1"]
            ),
        )
        storage_client = mock.MagicMock()
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    resouce_group_name="rg",
                    enable_https_traffic_only=True,
                    infrastructure_encryption=True,
                    allow_blob_public_access=False,
                    network_rule_set=NetworkRuleSet(
                        bypass="AzureServices", default_action="Allow"
                    ),
                    encryption_type="type",
                    minimum_tls_version="TLS1_2",
                    private_endpoint_connections=[],
                    key_expiration_period_in_days=None,
                    location="eastus",
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
                "prowler.providers.azure.services.storage.storage_smb_protocol_version_is_latest.storage_smb_protocol_version_is_latest.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_smb_protocol_version_is_latest.storage_smb_protocol_version_is_latest import (
                storage_smb_protocol_version_is_latest,
            )

            check = storage_smb_protocol_version_is_latest()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_ID} allows SMB protocol versions: SMB2.1, SMB3.1.1. Only the latest SMB protocol version (SMB3.1.1) should be allowed."
                in result[0].status_extended
            )

    def test_no_smb_protocol_versions(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        file_service_properties = FileServiceProperties(
            id=storage_account_id,
            name="default",
            type="type",
            share_delete_retention_policy=DeleteRetentionPolicy(enabled=True, days=7),
            smb_protocol_settings=SMBProtocolSettings(
                channel_encryption=[], supported_versions=[]
            ),
        )
        storage_client = mock.MagicMock()
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    resouce_group_name="rg",
                    enable_https_traffic_only=True,
                    infrastructure_encryption=True,
                    allow_blob_public_access=False,
                    network_rule_set=NetworkRuleSet(
                        bypass="AzureServices", default_action="Allow"
                    ),
                    encryption_type="type",
                    minimum_tls_version="TLS1_2",
                    private_endpoint_connections=[],
                    key_expiration_period_in_days=None,
                    location="eastus",
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
                "prowler.providers.azure.services.storage.storage_smb_protocol_version_is_latest.storage_smb_protocol_version_is_latest.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_smb_protocol_version_is_latest.storage_smb_protocol_version_is_latest import (
                storage_smb_protocol_version_is_latest,
            )

            check = storage_smb_protocol_version_is_latest()
            result = check.execute()
            assert len(result) == 0

    def test_multiple_required_versions_custom_config(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        file_service_properties = FileServiceProperties(
            id=storage_account_id,
            name="default",
            type="type",
            share_delete_retention_policy=DeleteRetentionPolicy(enabled=True, days=7),
            smb_protocol_settings=SMBProtocolSettings(
                channel_encryption=[], supported_versions=["SMB3.1.1", "SMB3.0"]
            ),
        )
        storage_client = mock.MagicMock()
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    resouce_group_name="rg",
                    enable_https_traffic_only=True,
                    infrastructure_encryption=True,
                    allow_blob_public_access=False,
                    network_rule_set=NetworkRuleSet(
                        bypass="AzureServices", default_action="Allow"
                    ),
                    encryption_type="type",
                    minimum_tls_version="TLS1_2",
                    private_endpoint_connections=[],
                    key_expiration_period_in_days=None,
                    location="eastus",
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
                "prowler.providers.azure.services.storage.storage_smb_protocol_version_is_latest.storage_smb_protocol_version_is_latest.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_smb_protocol_version_is_latest.storage_smb_protocol_version_is_latest import (
                storage_smb_protocol_version_is_latest,
            )

            check = storage_smb_protocol_version_is_latest()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_ID} allows SMB protocol versions: SMB3.1.1, SMB3.0. Only the latest SMB protocol version (SMB3.1.1) should be allowed."
                in result[0].status_extended
            )
