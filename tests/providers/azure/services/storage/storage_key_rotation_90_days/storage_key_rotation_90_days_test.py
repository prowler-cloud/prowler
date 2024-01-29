from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.storage.storage_service import Storage_Account
from tests.providers.azure.azure_fixtures import AZURE_SUSCRIPTION


class Test_storage_key_rotation_90_dayss:
    def test_storage_no_storage_accounts(self):
        storage_client = mock.MagicMock
        storage_client.storage_accounts = {}

        with mock.patch(
            "prowler.providers.azure.services.storage.storage_key_rotation_90_days.storage_key_rotation_90_days.storage_client",
            new=storage_client,
        ):
            from prowler.providers.azure.services.storage.storage_key_rotation_90_days.storage_key_rotation_90_days import (
                storage_key_rotation_90_days,
            )

            check = storage_key_rotation_90_days()
            result = check.execute()
            assert len(result) == 0

    def test_storage_storage_key_rotation_91_days(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        expiration_days = 91
        storage_client = mock.MagicMock
        storage_client.storage_accounts = {
            AZURE_SUSCRIPTION: [
                Storage_Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    enable_https_traffic_only=False,
                    infrastructure_encryption=False,
                    allow_blob_public_access=None,
                    network_rule_set=None,
                    encryption_type="None",
                    minimum_tls_version="TLS1_1",
                    key_expiration_period_in_days=expiration_days,
                    private_endpoint_connections=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.storage.storage_key_rotation_90_days.storage_key_rotation_90_days.storage_client",
            new=storage_client,
        ):
            from prowler.providers.azure.services.storage.storage_key_rotation_90_days.storage_key_rotation_90_days import (
                storage_key_rotation_90_days,
            )

            check = storage_key_rotation_90_days()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUSCRIPTION} has an invalid key expiration period of {expiration_days} days."
            )
            assert result[0].subscription == AZURE_SUSCRIPTION
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id

    def test_storage_storage_key_rotation_90_days(self):
        storage_account_id = str(uuid4())
        storage_account_name = "Test Storage Account"
        expiration_days = 90
        storage_client = mock.MagicMock
        storage_client.storage_accounts = {
            AZURE_SUSCRIPTION: [
                Storage_Account(
                    id=storage_account_id,
                    name=storage_account_name,
                    enable_https_traffic_only=False,
                    infrastructure_encryption=False,
                    allow_blob_public_access=None,
                    network_rule_set=None,
                    encryption_type="None",
                    minimum_tls_version="TLS1_2",
                    key_expiration_period_in_days=expiration_days,
                    private_endpoint_connections=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.storage.storage_key_rotation_90_days.storage_key_rotation_90_days.storage_client",
            new=storage_client,
        ):
            from prowler.providers.azure.services.storage.storage_key_rotation_90_days.storage_key_rotation_90_days import (
                storage_key_rotation_90_days,
            )

            check = storage_key_rotation_90_days()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUSCRIPTION} has a key expiration period of {expiration_days} days."
            )
            assert result[0].subscription == AZURE_SUSCRIPTION
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id

    def test_storage_storage_no_key_rotation(self):
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
                    allow_blob_public_access=None,
                    network_rule_set=None,
                    encryption_type="None",
                    minimum_tls_version="TLS1_2",
                    key_expiration_period_in_days=None,
                    private_endpoint_connections=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.storage.storage_key_rotation_90_days.storage_key_rotation_90_days.storage_client",
            new=storage_client,
        ):
            from prowler.providers.azure.services.storage.storage_key_rotation_90_days.storage_key_rotation_90_days import (
                storage_key_rotation_90_days,
            )

            check = storage_key_rotation_90_days()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUSCRIPTION} has no key expiration period set."
            )
            assert result[0].subscription == AZURE_SUSCRIPTION
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id
