from unittest.mock import patch

from prowler.providers.azure.services.storage.storage_service import (
    Account,
    BlobProperties,
    DeleteRetentionPolicy,
    FileServiceProperties,
    ReplicationSettings,
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
        container_delete_retention_policy=None,
    )
    retention_policy = DeleteRetentionPolicy(enabled=True, days=7)
    file_service_properties = FileServiceProperties(
        id="id",
        name="name",
        type="type",
        share_delete_retention_policy=retention_policy,
    )
    return {
        AZURE_SUBSCRIPTION_ID: [
            Account(
                id="id",
                name="name",
                resouce_group_name=None,
                enable_https_traffic_only=False,
                infrastructure_encryption=False,
                allow_blob_public_access=None,
                network_rule_set=None,
                encryption_type="None",
                minimum_tls_version=None,
                key_expiration_period_in_days=None,
                private_endpoint_connections=None,
                location="westeurope",
                blob_properties=blob_properties,
                default_to_entra_authorization=True,
                replication_settings=ReplicationSettings.STANDARD_LRS,
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
            is None
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
            is None
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0].network_rule_set is None
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0].encryption_type == "None"
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0].location == "westeurope"
        )
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0].minimum_tls_version
            is None
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
            is None
        )
        assert storage.storage_accounts[AZURE_SUBSCRIPTION_ID][
            0
        ].blob_properties == BlobProperties(
            id="id",
            name="name",
            type="type",
            default_service_version=None,
            container_delete_retention_policy=None,
        )
        assert storage.storage_accounts[AZURE_SUBSCRIPTION_ID][
            0
        ].default_to_entra_authorization
        assert (
            storage.storage_accounts[AZURE_SUBSCRIPTION_ID][0].replication_settings
            == ReplicationSettings.STANDARD_LRS
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
            is None
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
