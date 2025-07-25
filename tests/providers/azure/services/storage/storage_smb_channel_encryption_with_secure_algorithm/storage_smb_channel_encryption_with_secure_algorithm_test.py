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


class Test_storage_smb_channel_encryption_with_secure_algorithm:
    def test_no_storage_accounts(self):
        storage_client = mock.MagicMock()
        storage_client.storage_accounts = {}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.storage.storage_smb_channel_encryption_with_secure_algorithm.storage_smb_channel_encryption_with_secure_algorithm.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_smb_channel_encryption_with_secure_algorithm.storage_smb_channel_encryption_with_secure_algorithm import (
                storage_smb_channel_encryption_with_secure_algorithm,
            )

            check = storage_smb_channel_encryption_with_secure_algorithm()
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
                "prowler.providers.azure.services.storage.storage_smb_channel_encryption_with_secure_algorithm.storage_smb_channel_encryption_with_secure_algorithm.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_smb_channel_encryption_with_secure_algorithm.storage_smb_channel_encryption_with_secure_algorithm import (
                storage_smb_channel_encryption_with_secure_algorithm,
            )

            check = storage_smb_channel_encryption_with_secure_algorithm()
            result = check.execute()
            assert len(result) == 0

    def test_no_smb_protocol_settings(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        file_service_properties = FileServiceProperties(
            id="id1",
            name="fs1",
            type="type1",
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
                "prowler.providers.azure.services.storage.storage_smb_channel_encryption_with_secure_algorithm.storage_smb_channel_encryption_with_secure_algorithm.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_smb_channel_encryption_with_secure_algorithm.storage_smb_channel_encryption_with_secure_algorithm import (
                storage_smb_channel_encryption_with_secure_algorithm,
            )

            check = storage_smb_channel_encryption_with_secure_algorithm()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_ID} does not have SMB channel encryption enabled for file shares."
            )

    def test_not_recommended_encryption(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        file_service_properties = FileServiceProperties(
            id="id1",
            name="fs1",
            type="type1",
            share_delete_retention_policy=DeleteRetentionPolicy(enabled=True, days=7),
            smb_protocol_settings=SMBProtocolSettings(
                channel_encryption=["AES-128-GCM"], supported_versions=[]
            ),
        )
        storage_client = mock.MagicMock()
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
                "prowler.providers.azure.services.storage.storage_smb_channel_encryption_with_secure_algorithm.storage_smb_channel_encryption_with_secure_algorithm.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_smb_channel_encryption_with_secure_algorithm.storage_smb_channel_encryption_with_secure_algorithm import (
                storage_smb_channel_encryption_with_secure_algorithm,
            )

            check = storage_smb_channel_encryption_with_secure_algorithm()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_ID} does not have SMB channel encryption with a secure algorithm for file shares since it supports AES-128-GCM."
            )

    def test_recommended_encryption(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        file_service_properties = FileServiceProperties(
            id="id1",
            name="fs1",
            type="type1",
            share_delete_retention_policy=DeleteRetentionPolicy(enabled=True, days=7),
            smb_protocol_settings=SMBProtocolSettings(
                channel_encryption=["AES-256-GCM"], supported_versions=[]
            ),
        )
        storage_client = mock.MagicMock()
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
                "prowler.providers.azure.services.storage.storage_smb_channel_encryption_with_secure_algorithm.storage_smb_channel_encryption_with_secure_algorithm.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_smb_channel_encryption_with_secure_algorithm.storage_smb_channel_encryption_with_secure_algorithm import (
                storage_smb_channel_encryption_with_secure_algorithm,
            )

            check = storage_smb_channel_encryption_with_secure_algorithm()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION_ID} has a secure algorithm for SMB channel encryption (AES-256-GCM) enabled for file shares since it supports AES-256-GCM."
            )
