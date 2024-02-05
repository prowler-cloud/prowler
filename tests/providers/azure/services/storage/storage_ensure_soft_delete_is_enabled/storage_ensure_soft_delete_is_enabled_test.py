from unittest import mock
from uuid import uuid4

from azure.mgmt.storage.v2023_01_01.models import DeleteRetentionPolicy

from prowler.providers.azure.services.storage.storage_service import (
    Blob_Properties,
    Storage_Account,
)

AZURE_SUSCRIPTION = str(uuid4())


class Test_storage_ensure_soft_delete_is_enabled:
    def test_storage_no_storage_accounts(self):
        storage_client = mock.MagicMock
        storage_client.storage_accounts = {}

        with mock.patch(
            "prowler.providers.azure.services.storage.storage_ensure_soft_delete_is_enabled.storage_ensure_soft_delete_is_enabled.storage_client",
            new=storage_client,
        ):
            from prowler.providers.azure.services.storage.storage_ensure_soft_delete_is_enabled.storage_ensure_soft_delete_is_enabled import (
                storage_ensure_soft_delete_is_enabled,
            )

            check = storage_ensure_soft_delete_is_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_storage_no_blob_properties(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        storage_client = mock.MagicMock
        storage_account_blob_properties = None
        storage_client.storage_accounts = {
            AZURE_SUSCRIPTION: [
                Storage_Account(
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
                    private_endpoint_connections=None,
                    blob_properties=storage_account_blob_properties,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.storage.storage_ensure_soft_delete_is_enabled.storage_ensure_soft_delete_is_enabled.storage_client",
            new=storage_client,
        ):
            from prowler.providers.azure.services.storage.storage_ensure_soft_delete_is_enabled.storage_ensure_soft_delete_is_enabled import (
                storage_ensure_soft_delete_is_enabled,
            )

            check = storage_ensure_soft_delete_is_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_storage_ensure_soft_delete_is_disabled(
        self,
    ):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        storage_client = mock.MagicMock
        storage_account_blob_properties = Blob_Properties(
            id=None,
            name=None,
            type=None,
            default_service_version=None,
            container_delete_retention_policy=DeleteRetentionPolicy(enabled=False),
        )
        storage_client.storage_accounts = {
            AZURE_SUSCRIPTION: [
                Storage_Account(
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
                    private_endpoint_connections=None,
                    blob_properties=storage_account_blob_properties,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.storage.storage_ensure_soft_delete_is_enabled.storage_ensure_soft_delete_is_enabled.storage_client",
            new=storage_client,
        ):
            from prowler.providers.azure.services.storage.storage_ensure_soft_delete_is_enabled.storage_ensure_soft_delete_is_enabled import (
                storage_ensure_soft_delete_is_enabled,
            )

            check = storage_ensure_soft_delete_is_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUSCRIPTION} has soft delete disabled."
            )
            assert result[0].subscription == AZURE_SUSCRIPTION
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id

    def test_storage_ensure_soft_delete_is_enabled(
        self,
    ):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        storage_client = mock.MagicMock
        storage_account_blob_properties = Blob_Properties(
            id=None,
            name=None,
            type=None,
            default_service_version=None,
            container_delete_retention_policy=DeleteRetentionPolicy(enabled=True),
        )
        storage_client.storage_accounts = {
            AZURE_SUSCRIPTION: [
                Storage_Account(
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
                    private_endpoint_connections=None,
                    blob_properties=storage_account_blob_properties,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.storage.storage_ensure_soft_delete_is_enabled.storage_ensure_soft_delete_is_enabled.storage_client",
            new=storage_client,
        ):
            from prowler.providers.azure.services.storage.storage_ensure_soft_delete_is_enabled.storage_ensure_soft_delete_is_enabled import (
                storage_ensure_soft_delete_is_enabled,
            )

            check = storage_ensure_soft_delete_is_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUSCRIPTION} has soft delete enabled."
            )
            assert result[0].subscription == AZURE_SUSCRIPTION
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id
