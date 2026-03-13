from unittest.mock import patch

from prowler.providers.azure.services.storage.storage_service import (
    Account,
    BlobProperties,
    DeleteRetentionPolicy,
    FileServiceProperties,
    NetworkRuleSet,
    SMBProtocolSettings,
    Storage,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


def mock_storage_get_storage_accounts(_):
    blob_properties = BlobProperties(
        id="id",
        name="name",
        type="type",
        default_service_version=None,
        container_delete_retention_policy=DeleteRetentionPolicy(enabled=True, days=7),
    )
    retention_policy = DeleteRetentionPolicy(enabled=True, days=7)
    file_service_properties = FileServiceProperties(
        id="id",
        name="name",
        type="type",
        share_delete_retention_policy=retention_policy,
        smb_protocol_settings=SMBProtocolSettings(
            channel_encryption=[], supported_versions=[]
        ),
    )
    return {
        AZURE_SUBSCRIPTION_ID: [
            Account(
                id="id",
                name="name",
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
                private_endpoint_connections=[],
                location="westeurope",
                blob_properties=blob_properties,
                default_to_entra_authorization=True,
                replication_settings="Standard_LRS",
                allow_cross_tenant_replication=True,
                allow_shared_key_access=True,
                file_service_properties=file_service_properties,
            )
        ]
    }


@patch(
    "prowler.providers.azure.services.storage.storage_service.Storage._get_storage_accounts",
    new=mock_storage_get_storage_accounts,
)
class Test_Storage_Service:
    def test_get_client(self):
        storage = Storage(set_mocked_azure_provider())
        assert (
            storage.clients[AZURE_SUBSCRIPTION_ID].__class__.__name__
            == "StorageManagementClient"
        )

    def test_get_storage_accounts(self):
        storage = Storage(set_mocked_azure_provider())
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0].__class__.__name__
            == "Account"
        )
        assert storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0].id == "id"
        assert storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0].name == "name"
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0].resouce_group_name
            == "rg"
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0].enable_https_traffic_only
            is False
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0].infrastructure_encryption
            is False
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0].allow_blob_public_access
            is False
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0].network_rule_set
            is not None
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0].network_rule_set.bypass
            == "AzureServices"
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][
                0
            ].network_rule_set.default_action
            == "Allow"
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0].encryption_type == "None"
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0].location == "westeurope"
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0].minimum_tls_version
            == "TLS1_2"
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][
                0
            ].key_expiration_period_in_days
            is None
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][
                0
            ].private_endpoint_connections
            == []
        )
        assert storage.storage_accounts[AZURE_SUBSCRIPTION_ID][
            0
        ].blob_properties == BlobProperties(
            id="id",
            name="name",
            type="type",
            default_service_version=None,
            container_delete_retention_policy=DeleteRetentionPolicy(
                enabled=True, days=7
            ),
        )
        assert storage.storage_accounts[AZURE_SUBSCRIPTION_ID][
            0
        ].default_to_entra_authorization
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0].replication_settings
            == "Standard_LRS"
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][
                0
            ].allow_cross_tenant_replication
            is True
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0].allow_shared_key_access
            is True
        )

    def test_get_blob_properties(self):
        storage = Storage(set_mocked_azure_provider())
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][
                0
            ].blob_properties.__class__.__name__
            == "BlobProperties"
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0].blob_properties.id
            == "id"
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0].blob_properties.name
            == "name"
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0].blob_properties.type
            == "type"
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][
                0
            ].blob_properties.default_service_version
            is None
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][
                0
            ].blob_properties.container_delete_retention_policy
            is not None
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][
                0
            ].blob_properties.container_delete_retention_policy.enabled
            is True
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][
                0
            ].blob_properties.container_delete_retention_policy.days
            == 7
        )

    def test_get_file_service_properties(self):
        storage = Storage(set_mocked_azure_provider())
        account = storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0]
        assert hasattr(account, "file_service_properties")
        assert (
            account.file_service_properties.share_delete_retention_policy.enabled
            is True
        )
        assert account.file_service_properties.share_delete_retention_policy.days == 7
        assert (
            account.file_service_properties.smb_protocol_settings.channel_encryption
            == []
        )
        assert (
            account.file_service_properties.smb_protocol_settings.supported_versions
            == []
        )


def mock_storage_get_storage_accounts_with_none(_):
    """Mock storage accounts with None values in retention policies"""
    blob_properties_none_days = BlobProperties(
        id="id-none-days",
        name="name-none-days",
        type="type",
        default_service_version="2019-07-07",
        container_delete_retention_policy=DeleteRetentionPolicy(
            enabled=True, days=0  # None converted to 0
        ),
        versioning_enabled=False,
    )
    blob_properties_none_enabled = BlobProperties(
        id="id-none-enabled",
        name="name-none-enabled",
        type="type",
        default_service_version=None,
        container_delete_retention_policy=DeleteRetentionPolicy(
            enabled=False, days=30  # None enabled converted to False
        ),
        versioning_enabled=True,
    )
    file_service_properties_none_days = FileServiceProperties(
        id="id-file-none",
        name="name-file-none",
        type="type",
        share_delete_retention_policy=DeleteRetentionPolicy(
            enabled=False, days=0  # None converted to 0
        ),
        smb_protocol_settings=SMBProtocolSettings(
            channel_encryption=[], supported_versions=[]
        ),
    )
    return {
        AZURE_SUBSCRIPTION_ID: [
            Account(
                id="id-none-days",
                name="storage-none-days",
                resouce_group_name="rg",
                enable_https_traffic_only=True,
                infrastructure_encryption=False,
                allow_blob_public_access=False,
                network_rule_set=NetworkRuleSet(
                    bypass="AzureServices", default_action="Allow"
                ),
                encryption_type="Microsoft.Storage",
                minimum_tls_version="TLS1_2",
                key_expiration_period_in_days=None,
                private_endpoint_connections=[],
                location="eastus",
                blob_properties=blob_properties_none_days,
                default_to_entra_authorization=False,
                replication_settings="Standard_LRS",
                allow_cross_tenant_replication=True,
                allow_shared_key_access=True,
                file_service_properties=None,
            ),
            Account(
                id="id-none-enabled",
                name="storage-none-enabled",
                resouce_group_name="rg2",
                enable_https_traffic_only=True,
                infrastructure_encryption=False,
                allow_blob_public_access=True,
                network_rule_set=NetworkRuleSet(bypass="None", default_action="Deny"),
                encryption_type="Microsoft.Storage",
                minimum_tls_version="TLS1_2",
                key_expiration_period_in_days=None,
                private_endpoint_connections=[],
                location="northeurope",
                blob_properties=blob_properties_none_enabled,
                default_to_entra_authorization=False,
                replication_settings="Premium_LRS",
                allow_cross_tenant_replication=False,
                allow_shared_key_access=False,
                file_service_properties=None,
            ),
            Account(
                id="id-file-none",
                name="storage-file-none",
                resouce_group_name="rg3",
                enable_https_traffic_only=True,
                infrastructure_encryption=True,
                allow_blob_public_access=False,
                network_rule_set=NetworkRuleSet(
                    bypass="AzureServices", default_action="Deny"
                ),
                encryption_type="Microsoft.Keyvault",
                minimum_tls_version="TLS1_2",
                key_expiration_period_in_days=None,
                private_endpoint_connections=[],
                location="westus",
                blob_properties=None,
                default_to_entra_authorization=False,
                replication_settings="Standard_GRS",
                allow_cross_tenant_replication=True,
                allow_shared_key_access=True,
                file_service_properties=file_service_properties_none_days,
            ),
        ]
    }


@patch(
    "prowler.providers.azure.services.storage.storage_service.Storage._get_storage_accounts",
    new=mock_storage_get_storage_accounts_with_none,
)
class Test_Storage_Service_Retention_Policy_None_Handling:
    """Test Storage service handling of None values in retention policies"""

    def test_blob_properties_with_none_retention_days(self):
        """Test that Storage handles None days in container_delete_retention_policy"""
        storage = Storage(set_mocked_azure_provider())

        # Find account with None days converted to 0
        account = next(
            acc
            for acc in storage.storage_accounts[AZURE_SUBSCRIPTION_ID]
            if acc.name == "storage-none-days"
        )
        assert account.blob_properties is not None
        assert account.blob_properties.container_delete_retention_policy.enabled is True
        assert account.blob_properties.container_delete_retention_policy.days == 0

    def test_blob_properties_with_none_retention_enabled(self):
        """Test that Storage handles None enabled in retention policy"""
        storage = Storage(set_mocked_azure_provider())

        # Find account with None enabled converted to False
        account = next(
            acc
            for acc in storage.storage_accounts[AZURE_SUBSCRIPTION_ID]
            if acc.name == "storage-none-enabled"
        )
        assert account.blob_properties is not None
        assert (
            account.blob_properties.container_delete_retention_policy.enabled is False
        )
        assert account.blob_properties.container_delete_retention_policy.days == 30

    def test_file_service_properties_with_none_retention_days(self):
        """Test that Storage handles None days in share_delete_retention_policy"""
        storage = Storage(set_mocked_azure_provider())

        # Find account with None days in file service
        account = next(
            acc
            for acc in storage.storage_accounts[AZURE_SUBSCRIPTION_ID]
            if acc.name == "storage-file-none"
        )
        assert account.file_service_properties is not None
        assert (
            account.file_service_properties.share_delete_retention_policy.enabled
            is False
        )
        assert account.file_service_properties.share_delete_retention_policy.days == 0
