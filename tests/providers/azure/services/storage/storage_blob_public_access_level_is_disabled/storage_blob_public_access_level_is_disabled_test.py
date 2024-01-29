from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.storage.storage_service import Storage_Account

AZURE_SUSCRIPTION = str(uuid4())


class Test_storage_blob_public_access_level_is_disabled:
    def test_storage_no_storage_accounts(self):
        storage_client = mock.MagicMock
        storage_client.storage_accounts = {}

        with mock.patch(
            "prowler.providers.azure.services.storage.storage_blob_public_access_level_is_disabled.storage_blob_public_access_level_is_disabled.storage_client",
            new=storage_client,
        ):
            from prowler.providers.azure.services.storage.storage_blob_public_access_level_is_disabled.storage_blob_public_access_level_is_disabled import (
                storage_blob_public_access_level_is_disabled,
            )

            check = storage_blob_public_access_level_is_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_storage_storage_accounts_public_access_level_enabled(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        storage_client = mock.MagicMock
        storage_client.storage_accounts = {
            AZURE_SUSCRIPTION: [
                Storage_Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    enable_https_traffic_only=False,
                    infrastructure_encryption=False,
                    allow_blob_public_access=True,
                    network_rule_set=None,
                    encryption_type=None,
                    minimum_tls_version=None,
                    key_expiration_period_in_days=None,
                    private_endpoint_connections=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.storage.storage_blob_public_access_level_is_disabled.storage_blob_public_access_level_is_disabled.storage_client",
            new=storage_client,
        ):
            from prowler.providers.azure.services.storage.storage_blob_public_access_level_is_disabled.storage_blob_public_access_level_is_disabled import (
                storage_blob_public_access_level_is_disabled,
            )

            check = storage_blob_public_access_level_is_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUSCRIPTION} has allow blob public access enabled."
            )
            assert result[0].subscription == AZURE_SUSCRIPTION
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id

    def test_storage_storage_accounts_public_access_level_disabled(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        storage_client = mock.MagicMock
        storage_client.storage_accounts = {
            AZURE_SUSCRIPTION: [
                Storage_Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    enable_https_traffic_only=False,
                    infrastructure_encryption=False,
                    allow_blob_public_access=False,
                    network_rule_set=None,
                    encryption_type=None,
                    minimum_tls_version=None,
                    key_expiration_period_in_days=None,
                    private_endpoint_connections=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.storage.storage_blob_public_access_level_is_disabled.storage_blob_public_access_level_is_disabled.storage_client",
            new=storage_client,
        ):
            from prowler.providers.azure.services.storage.storage_blob_public_access_level_is_disabled.storage_blob_public_access_level_is_disabled import (
                storage_blob_public_access_level_is_disabled,
            )

            check = storage_blob_public_access_level_is_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUSCRIPTION} has allow blob public access disabled."
            )
            assert result[0].subscription == AZURE_SUSCRIPTION
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id
