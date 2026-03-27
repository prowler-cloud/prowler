from unittest import mock
from uuid import uuid4

from azure.mgmt.keyvault.v2023_07_01.models import KeyAttributes, VaultProperties

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_keyvault_rbac_key_expiration_set:
    def test_no_key_vaults(self):
        keyvault_client = mock.MagicMock
        keyvault_client.key_vaults = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.keyvault.keyvault_rbac_key_expiration_set.keyvault_rbac_key_expiration_set.keyvault_client",
                new=keyvault_client,
            ),
        ):
            from prowler.providers.azure.services.keyvault.keyvault_rbac_key_expiration_set.keyvault_rbac_key_expiration_set import (
                keyvault_rbac_key_expiration_set,
            )

            check = keyvault_rbac_key_expiration_set()
            result = check.execute()
            assert len(result) == 0

    def test_no_keys(self):
        keyvault_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.keyvault.keyvault_rbac_key_expiration_set.keyvault_rbac_key_expiration_set.keyvault_client",
                new=keyvault_client,
            ),
        ):
            from prowler.providers.azure.services.keyvault.keyvault_rbac_key_expiration_set.keyvault_rbac_key_expiration_set import (
                keyvault_rbac_key_expiration_set,
            )
            from prowler.providers.azure.services.keyvault.keyvault_service import (
                KeyVaultInfo,
            )

            keyvault_client.key_vaults = {
                AZURE_SUBSCRIPTION_ID: [
                    KeyVaultInfo(
                        id="id",
                        name="name",
                        location="westeurope",
                        resource_group="resource_group",
                        properties=VaultProperties(
                            tenant_id="tenantid",
                            sku="sku",
                            enable_rbac_authorization=True,
                        ),
                        keys=[],
                        secrets=[],
                    )
                ]
            }
            check = keyvault_rbac_key_expiration_set()
            result = check.execute()
            assert len(result) == 0

    def test_key_vaults_invalid_keys(self):
        keyvault_client = mock.MagicMock
        keyvault_name = "Keyvault Name"
        keyvault_id = str(uuid4())
        key_name = "Key Name"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.keyvault.keyvault_rbac_key_expiration_set.keyvault_rbac_key_expiration_set.keyvault_client",
                new=keyvault_client,
            ),
        ):
            from prowler.providers.azure.services.keyvault.keyvault_rbac_key_expiration_set.keyvault_rbac_key_expiration_set import (
                keyvault_rbac_key_expiration_set,
            )
            from prowler.providers.azure.services.keyvault.keyvault_service import (
                Key,
                KeyVaultInfo,
            )

            key = Key(
                id="id",
                name=key_name,
                enabled=True,
                location="location",
                attributes=KeyAttributes(expires=None, enabled=True),
            )
            keyvault_client.key_vaults = {
                AZURE_SUBSCRIPTION_ID: [
                    KeyVaultInfo(
                        id=keyvault_id,
                        name=keyvault_name,
                        location="westeurope",
                        resource_group="resource_group",
                        properties=VaultProperties(
                            tenant_id="tenantid",
                            sku="sku",
                            enable_rbac_authorization=True,
                        ),
                        keys=[key],
                        secrets=[],
                    )
                ]
            }
            check = keyvault_rbac_key_expiration_set()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Key {key_name} in Key Vault {keyvault_name} from subscription {AZURE_SUBSCRIPTION_ID} does not have an expiration date set."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == key_name
            assert result[0].resource_id == "id"
            assert result[0].location == "location"

    def test_key_vaults_valid_keys(self):
        keyvault_client = mock.MagicMock
        keyvault_name = "Keyvault Name"
        keyvault_id = str(uuid4())
        key_name = "Key Name"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.keyvault.keyvault_rbac_key_expiration_set.keyvault_rbac_key_expiration_set.keyvault_client",
                new=keyvault_client,
            ),
        ):
            from prowler.providers.azure.services.keyvault.keyvault_rbac_key_expiration_set.keyvault_rbac_key_expiration_set import (
                keyvault_rbac_key_expiration_set,
            )
            from prowler.providers.azure.services.keyvault.keyvault_service import (
                Key,
                KeyVaultInfo,
            )

            key = Key(
                id="id",
                name=key_name,
                enabled=True,
                location="location",
                attributes=KeyAttributes(expires=49394, enabled=True),
            )
            keyvault_client.key_vaults = {
                AZURE_SUBSCRIPTION_ID: [
                    KeyVaultInfo(
                        id=keyvault_id,
                        name=keyvault_name,
                        location="westeurope",
                        resource_group="resource_group",
                        properties=VaultProperties(
                            tenant_id="tenantid",
                            sku="sku",
                            enable_rbac_authorization=True,
                        ),
                        keys=[key],
                        secrets=[],
                    )
                ]
            }
            check = keyvault_rbac_key_expiration_set()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Key {key_name} in Key Vault {keyvault_name} from subscription {AZURE_SUBSCRIPTION_ID} has an expiration date set."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == key_name
            assert result[0].resource_id == "id"
            assert result[0].location == "location"

    def test_multiple_keys_mixed_expiration(self):
        keyvault_client = mock.MagicMock
        keyvault_name = "Keyvault Name"
        keyvault_id = str(uuid4())
        key_with_expiry = "key_with_expiry"
        key_without_expiry = "key_without_expiry"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.keyvault.keyvault_rbac_key_expiration_set.keyvault_rbac_key_expiration_set.keyvault_client",
                new=keyvault_client,
            ),
        ):
            from prowler.providers.azure.services.keyvault.keyvault_rbac_key_expiration_set.keyvault_rbac_key_expiration_set import (
                keyvault_rbac_key_expiration_set,
            )
            from prowler.providers.azure.services.keyvault.keyvault_service import (
                Key,
                KeyVaultInfo,
            )

            keyvault_client.key_vaults = {
                AZURE_SUBSCRIPTION_ID: [
                    KeyVaultInfo(
                        id=keyvault_id,
                        name=keyvault_name,
                        location="westeurope",
                        resource_group="resource_group",
                        properties=VaultProperties(
                            tenant_id="tenantid",
                            sku="sku",
                            enable_rbac_authorization=True,
                        ),
                        keys=[
                            Key(
                                id="id1",
                                name=key_without_expiry,
                                enabled=True,
                                location="location",
                                attributes=KeyAttributes(expires=None, enabled=True),
                            ),
                            Key(
                                id="id2",
                                name=key_with_expiry,
                                enabled=True,
                                location="location",
                                attributes=KeyAttributes(expires=49394, enabled=True),
                            ),
                        ],
                        secrets=[],
                    )
                ]
            }
            check = keyvault_rbac_key_expiration_set()
            result = check.execute()
            assert len(result) == 2
            assert result[0] is not result[1]
            assert result[0].status == "FAIL"
            assert key_without_expiry in result[0].status_extended
            assert result[1].status == "PASS"
            assert key_with_expiry in result[1].status_extended
