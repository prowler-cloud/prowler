from unittest import mock
from uuid import uuid4

from azure.mgmt.storage.v2022_09_01.models import NetworkRuleSet

from prowler.providers.azure.services.storage.storage_service import Storage_Account

AZURE_SUSCRIPTION = str(uuid4())


class Test_storage_default_network_access_rule_is_denied:
    def test_storage_no_storage_accounts(self):
        storage_client = mock.MagicMock
        storage_client.storage_accounts = {}

        with mock.patch(
            "prowler.providers.azure.services.storage.storage_default_network_access_rule_is_denied.storage_default_network_access_rule_is_denied.storage_client",
            new=storage_client,
        ):
            from prowler.providers.azure.services.storage.storage_default_network_access_rule_is_denied.storage_default_network_access_rule_is_denied import (
                storage_default_network_access_rule_is_denied,
            )

            check = storage_default_network_access_rule_is_denied()
            result = check.execute()
            assert len(result) == 0

    def test_storage_storage_accounts_default_network_access_rule_allowed(self):
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
                    network_rule_set=NetworkRuleSet(default_action="Allow"),
                    encryption_type=None,
                    minimum_tls_version=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.storage.storage_default_network_access_rule_is_denied.storage_default_network_access_rule_is_denied.storage_client",
            new=storage_client,
        ):
            from prowler.providers.azure.services.storage.storage_default_network_access_rule_is_denied.storage_default_network_access_rule_is_denied import (
                storage_default_network_access_rule_is_denied,
            )

            check = storage_default_network_access_rule_is_denied()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUSCRIPTION} has network access rule set to Allow"
            )
            assert result[0].subscription == AZURE_SUSCRIPTION
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id

    def test_storage_storage_accounts_default_network_access_rule_denied(self):
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
                    network_rule_set=NetworkRuleSet(default_action="Deny"),
                    encryption_type=None,
                    minimum_tls_version=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.storage.storage_default_network_access_rule_is_denied.storage_default_network_access_rule_is_denied.storage_client",
            new=storage_client,
        ):
            from prowler.providers.azure.services.storage.storage_default_network_access_rule_is_denied.storage_default_network_access_rule_is_denied import (
                storage_default_network_access_rule_is_denied,
            )

            check = storage_default_network_access_rule_is_denied()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} from subscription {AZURE_SUSCRIPTION} has network access rule set to Deny"
            )
            assert result[0].subscription == AZURE_SUSCRIPTION
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id
