from unittest.mock import patch

from prowler.providers.azure.services.storage.storage_service import (
    Account,
    BlobProperties,
    Storage,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUSCRIPTION,
    set_mocked_azure_audit_info,
)


def mock_storage_get_storage_accounts(_):
    blob_properties = BlobProperties(
        id="id",
        name="name",
        type="type",
        default_service_version=None,
        container_delete_retention_policy=None,
    )
    return {
        AZURE_SUSCRIPTION: [
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
                blob_properties=blob_properties,
            )
        ]
    }


@patch(
    "prowler.providers.azure.services.storage.storage_service.Storage.__get_storage_accounts__",
    new=mock_storage_get_storage_accounts,
)
class Test_Storage_Service:
    def test__get_client__(self):
        storage = Storage(set_mocked_azure_audit_info())
        assert (
            storage.clients[AZURE_SUSCRIPTION].__class__.__name__
            == "StorageManagementClient"
        )

    def test__get_storage_accounts__(self):
        storage = Storage(set_mocked_azure_audit_info())
        assert (
            storage.storage_accounts[AZURE_SUSCRIPTION][0].__class__.__name__
            == "Account"
        )
        assert storage.storage_accounts[AZURE_SUSCRIPTION][0].id == "id"
        assert storage.storage_accounts[AZURE_SUSCRIPTION][0].name == "name"
        assert storage.storage_accounts[AZURE_SUSCRIPTION][0].resouce_group_name is None
        assert (
            storage.storage_accounts[AZURE_SUSCRIPTION][0].enable_https_traffic_only
            is False
        )
        assert (
            storage.storage_accounts[AZURE_SUSCRIPTION][0].infrastructure_encryption
            is False
        )
        assert (
            storage.storage_accounts[AZURE_SUSCRIPTION][0].allow_blob_public_access
            is None
        )
        assert storage.storage_accounts[AZURE_SUSCRIPTION][0].network_rule_set is None
        assert storage.storage_accounts[AZURE_SUSCRIPTION][0].encryption_type == "None"
        assert (
            storage.storage_accounts[AZURE_SUSCRIPTION][0].minimum_tls_version is None
        )
        assert (
            storage.storage_accounts[AZURE_SUSCRIPTION][0].key_expiration_period_in_days
            is None
        )
        assert (
            storage.storage_accounts[AZURE_SUSCRIPTION][0].private_endpoint_connections
            is None
        )
        assert storage.storage_accounts[AZURE_SUSCRIPTION][
            0
        ].blob_properties == BlobProperties(
            id="id",
            name="name",
            type="type",
            default_service_version=None,
            container_delete_retention_policy=None,
        )

    def test__get_blob_properties__(self):
        storage = Storage(set_mocked_azure_audit_info())
        assert (
            storage.storage_accounts[AZURE_SUSCRIPTION][
                0
            ].blob_properties.__class__.__name__
            == "BlobProperties"
        )
        assert storage.storage_accounts[AZURE_SUSCRIPTION][0].blob_properties.id == "id"
        assert (
            storage.storage_accounts[AZURE_SUSCRIPTION][0].blob_properties.name
            == "name"
        )
        assert (
            storage.storage_accounts[AZURE_SUSCRIPTION][0].blob_properties.type
            == "type"
        )
        assert (
            storage.storage_accounts[AZURE_SUSCRIPTION][
                0
            ].blob_properties.default_service_version
            is None
        )
        assert (
            storage.storage_accounts[AZURE_SUSCRIPTION][
                0
            ].blob_properties.container_delete_retention_policy
            is None
        )
