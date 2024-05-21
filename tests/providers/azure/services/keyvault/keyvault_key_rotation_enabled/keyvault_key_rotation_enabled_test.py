from unittest import mock

from azure.keyvault.keys import KeyRotationLifetimeAction, KeyRotationPolicy
from azure.mgmt.keyvault.v2023_07_01.models import KeyAttributes, VaultProperties

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_keyvault_key_rotation_enabled:
    def test_no_key_vaults(self):
        keyvault_client = mock.MagicMock
        keyvault_client.key_vaults = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_key_rotation_enabled.keyvault_key_rotation_enabled.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_key_rotation_enabled.keyvault_key_rotation_enabled import (
                keyvault_key_rotation_enabled,
            )

            check = keyvault_key_rotation_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_no_keys(self):
        keyvault_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_key_rotation_enabled.keyvault_key_rotation_enabled.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_key_rotation_enabled.keyvault_key_rotation_enabled import (
                keyvault_key_rotation_enabled,
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
                            enable_rbac_authorization=False,
                        ),
                        keys=[],
                        secrets=[],
                    )
                ]
            }
            check = keyvault_key_rotation_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_key_without_rotation_policy(self):
        keyvault_client = mock.MagicMock
        keyvault_name = "keyvault_name"
        key_name = "key_name"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_key_rotation_enabled.keyvault_key_rotation_enabled.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_key_rotation_enabled.keyvault_key_rotation_enabled import (
                keyvault_key_rotation_enabled,
            )
            from prowler.providers.azure.services.keyvault.keyvault_service import (
                Key,
                KeyVaultInfo,
            )

            keyvault_client.key_vaults = {
                AZURE_SUBSCRIPTION_ID: [
                    KeyVaultInfo(
                        id="id",
                        name=keyvault_name,
                        location="westeurope",
                        resource_group="resource_group",
                        properties=VaultProperties(
                            tenant_id="tenantid",
                            sku="sku",
                            enable_rbac_authorization=False,
                        ),
                        keys=[
                            Key(
                                id="id",
                                name=key_name,
                                enabled=True,
                                location="location",
                                attributes=KeyAttributes(expires=None, enabled=True),
                                rotation_policy=None,
                            )
                        ],
                        secrets=[],
                    )
                ]
            }
            check = keyvault_key_rotation_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Keyvault {keyvault_name} from subscription {AZURE_SUBSCRIPTION_ID} has the key {key_name} without rotation policy set."
            )
            assert result[0].resource_name == keyvault_name
            assert result[0].resource_id == "id"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "westeurope"

    def test_key_with_rotation_policy(self):
        keyvault_client = mock.MagicMock
        keyvault_name = "keyvault_name"
        key_name = "key_name"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_key_rotation_enabled.keyvault_key_rotation_enabled.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_key_rotation_enabled.keyvault_key_rotation_enabled import (
                keyvault_key_rotation_enabled,
            )
            from prowler.providers.azure.services.keyvault.keyvault_service import (
                Key,
                KeyVaultInfo,
            )

            keyvault_client.key_vaults = {
                AZURE_SUBSCRIPTION_ID: [
                    KeyVaultInfo(
                        id="id",
                        name=keyvault_name,
                        location="westeurope",
                        resource_group="resource_group",
                        properties=VaultProperties(
                            tenant_id="tenantid",
                            sku="sku",
                            enable_rbac_authorization=False,
                        ),
                        keys=[
                            Key(
                                id="id",
                                name=key_name,
                                enabled=True,
                                location="location",
                                attributes=KeyAttributes(expires=None, enabled=True),
                                rotation_policy=KeyRotationPolicy(
                                    lifetime_actions=[
                                        KeyRotationLifetimeAction(
                                            action="Rotate",
                                            lifetime_action_type="Rotate",
                                            lifetime_percentage=80,
                                        )
                                    ]
                                ),
                            )
                        ],
                        secrets=[],
                    )
                ]
            }
            check = keyvault_key_rotation_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Keyvault {keyvault_name} from subscription {AZURE_SUBSCRIPTION_ID} has the key {key_name} with rotation policy set."
            )
            assert result[0].resource_name == keyvault_name
            assert result[0].resource_id == "id"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "westeurope"
