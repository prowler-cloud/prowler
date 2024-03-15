from unittest import mock
from uuid import uuid4

from azure.mgmt.keyvault.v2023_07_01.models import KeyAttributes, VaultProperties

from prowler.providers.azure.services.keyvault.keyvault_service import Key, KeyVaultInfo
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_provider,
)


class Test_keyvault_key_expiration_set_in_non_rbac:
    def test_no_key_vaults(self):
        keyvault_client = mock.MagicMock
        keyvault_client.key_vaults = {}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_key_expiration_set_in_non_rbac.keyvault_key_expiration_set_in_non_rbac.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_key_expiration_set_in_non_rbac.keyvault_key_expiration_set_in_non_rbac import (
                keyvault_key_expiration_set_in_non_rbac,
            )

            check = keyvault_key_expiration_set_in_non_rbac()
            result = check.execute()
            assert len(result) == 0

    def test_no_keys(self):
        keyvault_client = mock.MagicMock
        keyvault_client.key_vaults = {
            AZURE_SUBSCRIPTION: [
                KeyVaultInfo(
                    id="id",
                    name="name",
                    location="location",
                    resource_group="resource_group",
                    properties=VaultProperties(
                        tenant_id="tenantid", sku="sku", enable_rbac_authorization=False
                    ),
                    keys=[],
                    secrets=[],
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_key_expiration_set_in_non_rbac.keyvault_key_expiration_set_in_non_rbac.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_key_expiration_set_in_non_rbac.keyvault_key_expiration_set_in_non_rbac import (
                keyvault_key_expiration_set_in_non_rbac,
            )

            check = keyvault_key_expiration_set_in_non_rbac()
            result = check.execute()
            assert len(result) == 0

    def test_key_vaults_invalid_keys(self):
        keyvault_client = mock.MagicMock
        keyvault_name = "Keyvault Name"
        keyvault_id = str(uuid4())
        key_name = "Key Name"
        key = Key(
            id="id",
            name=key_name,
            enabled=True,
            location="location",
            attributes=KeyAttributes(expires=None, enabled=True),
        )
        keyvault_client.key_vaults = {
            AZURE_SUBSCRIPTION: [
                KeyVaultInfo(
                    id=keyvault_id,
                    name=keyvault_name,
                    location="location",
                    resource_group="resource_group",
                    properties=VaultProperties(
                        tenant_id="tenantid", sku="sku", enable_rbac_authorization=False
                    ),
                    keys=[key],
                    secrets=[],
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_key_expiration_set_in_non_rbac.keyvault_key_expiration_set_in_non_rbac.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_key_expiration_set_in_non_rbac.keyvault_key_expiration_set_in_non_rbac import (
                keyvault_key_expiration_set_in_non_rbac,
            )

            check = keyvault_key_expiration_set_in_non_rbac()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Keyvault {keyvault_name} from subscription {AZURE_SUBSCRIPTION} has the key {key_name} without expiration date set."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == keyvault_name
            assert result[0].resource_id == keyvault_id

    def test_key_vaults_valid_keys(self):
        keyvault_client = mock.MagicMock
        keyvault_name = "Keyvault Name"
        keyvault_id = str(uuid4())
        key = Key(
            id="id",
            name="name",
            enabled=True,
            location="location",
            attributes=KeyAttributes(expires=49394, enabled=True),
        )
        keyvault_client.key_vaults = {
            AZURE_SUBSCRIPTION: [
                KeyVaultInfo(
                    id=keyvault_id,
                    name=keyvault_name,
                    location="location",
                    resource_group="resource_group",
                    properties=VaultProperties(
                        tenant_id="tenantid", sku="sku", enable_rbac_authorization=False
                    ),
                    keys=[key],
                    secrets=[],
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_key_expiration_set_in_non_rbac.keyvault_key_expiration_set_in_non_rbac.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_key_expiration_set_in_non_rbac.keyvault_key_expiration_set_in_non_rbac import (
                keyvault_key_expiration_set_in_non_rbac,
            )

            check = keyvault_key_expiration_set_in_non_rbac()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Keyvault {keyvault_name} from subscription {AZURE_SUBSCRIPTION} has all the keys with expiration date set."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == keyvault_name
            assert result[0].resource_id == keyvault_id
