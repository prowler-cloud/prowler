from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.storage.storage_service import Account

AZURE_SUBSCRIPTION = str(uuid4())


class Test_storage_infrastructure_encryption_is_enabled:
    def test_storage_no_storage_accounts(self):
        storage_client = mock.MagicMock
        storage_client.storage_accounts = {}

        with mock.patch(
            "prowler.providers.azure.services.storage.storage_infrastructure_encryption_is_enabled.storage_infrastructure_encryption_is_enabled.storage_client",
            new=storage_client,
        ):
            from prowler.providers.azure.services.storage.storage_infrastructure_encryption_is_enabled.storage_infrastructure_encryption_is_enabled import (
                storage_infrastructure_encryption_is_enabled,
            )

            check = storage_infrastructure_encryption_is_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_storage_storage_accounts_infrastructure_encryption_disabled(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        storage_client = mock.MagicMock
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION: [
                Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    resouce_group_name=None,
                    enable_https_traffic_only=False,
                    infrastructure_encryption=False,
                    allow_blob_public_access=None,
                    network_rule_set=None,
                    encryption_type="None",
                    minimum_tls_version="TLS1_1",
                    key_expiration_period_in_days=None,
                    private_endpoint_connections=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.storage.storage_infrastructure_encryption_is_enabled.storage_infrastructure_encryption_is_enabled.storage_client",
            new=storage_client,
        ):
            from prowler.providers.azure.services.storage.storage_infrastructure_encryption_is_enabled.storage_infrastructure_encryption_is_enabled import (
                storage_infrastructure_encryption_is_enabled,
            )

            check = storage_infrastructure_encryption_is_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION} has infrastructure encryption disabled."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id

    def test_storage_storage_accounts_infrastructure_encryption_enabled(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        storage_client = mock.MagicMock
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION: [
                Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    resouce_group_name=None,
                    enable_https_traffic_only=False,
                    infrastructure_encryption=True,
                    allow_blob_public_access=None,
                    network_rule_set=None,
                    encryption_type="None",
                    minimum_tls_version="TLS1_1",
                    key_expiration_period_in_days=None,
                    private_endpoint_connections=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.storage.storage_infrastructure_encryption_is_enabled.storage_infrastructure_encryption_is_enabled.storage_client",
            new=storage_client,
        ):
            from prowler.providers.azure.services.storage.storage_infrastructure_encryption_is_enabled.storage_infrastructure_encryption_is_enabled import (
                storage_infrastructure_encryption_is_enabled,
            )

            check = storage_infrastructure_encryption_is_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUBSCRIPTION} has infrastructure encryption enabled."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id
