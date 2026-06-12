from unittest import mock

from azure.keyvault.keys import KeyRotationLifetimeAction, KeyRotationPolicy
from azure.mgmt.keyvault.v2023_07_01.models import KeyAttributes, VaultProperties

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)


class Test_keyvault_key_rotation_enabled:
    def test_no_key_vaults(self):
        keyvault_client = mock.MagicMock
        keyvault_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        keyvault_client.key_vaults = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.keyvault.keyvault_key_rotation_enabled.keyvault_key_rotation_enabled.keyvault_client",
                new=keyvault_client,
            ),
        ):
            from prowler.providers.azure.services.keyvault.keyvault_key_rotation_enabled.keyvault_key_rotation_enabled import (
                keyvault_key_rotation_enabled,
            )

            check = keyvault_key_rotation_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_no_keys(self):
        keyvault_client = mock.MagicMock
        keyvault_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.keyvault.keyvault_key_rotation_enabled.keyvault_key_rotation_enabled.keyvault_client",
                new=keyvault_client,
            ),
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
        keyvault_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        keyvault_name = "keyvault_name"
        key_name = "key_name"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.keyvault.keyvault_key_rotation_enabled.keyvault_key_rotation_enabled.keyvault_client",
                new=keyvault_client,
            ),
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
                == f"Key {key_name} in Key Vault {keyvault_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} does not have a rotation policy set."
            )
            assert result[0].resource_name == key_name
            assert result[0].resource_id == "id"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "location"

    def test_key_with_rotation_policy(self):
        keyvault_client = mock.MagicMock
        keyvault_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        keyvault_name = "keyvault_name"
        key_name = "key_name"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.keyvault.keyvault_key_rotation_enabled.keyvault_key_rotation_enabled.keyvault_client",
                new=keyvault_client,
            ),
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
                == f"Key {key_name} in Key Vault {keyvault_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} has a rotation policy set."
            )
            assert result[0].resource_name == key_name
            assert result[0].resource_id == "id"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "location"

    def test_multiple_keys_mixed_rotation_policies(self):
        keyvault_client = mock.MagicMock
        keyvault_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        keyvault_name = "keyvault_name"
        key_with_rotation = "key_with_rotation"
        key_without_rotation = "key_without_rotation"
        key_with_notify_only = "key_with_notify_only"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.keyvault.keyvault_key_rotation_enabled.keyvault_key_rotation_enabled.keyvault_client",
                new=keyvault_client,
            ),
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
                                id="id1",
                                name=key_with_rotation,
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
                            ),
                            Key(
                                id="id2",
                                name=key_without_rotation,
                                enabled=True,
                                location="location",
                                attributes=KeyAttributes(expires=None, enabled=True),
                                rotation_policy=None,
                            ),
                            Key(
                                id="id3",
                                name=key_with_notify_only,
                                enabled=True,
                                location="location",
                                attributes=KeyAttributes(expires=None, enabled=True),
                                rotation_policy=KeyRotationPolicy(
                                    lifetime_actions=[
                                        KeyRotationLifetimeAction(
                                            action="Notify",
                                            lifetime_action_type="Notify",
                                            lifetime_percentage=90,
                                        )
                                    ]
                                ),
                            ),
                        ],
                        secrets=[],
                    )
                ]
            }
            check = keyvault_key_rotation_enabled()
            result = check.execute()
            assert len(result) == 3
            # Each finding must be a distinct object
            assert result[0] is not result[1]
            assert result[1] is not result[2]
            # Key with rotation policy -> PASS
            assert result[0].status == "PASS"
            assert key_with_rotation in result[0].status_extended
            # Key without rotation policy -> FAIL
            assert result[1].status == "FAIL"
            assert key_without_rotation in result[1].status_extended
            # Key with only Notify action (no Rotate) -> FAIL
            assert result[2].status == "FAIL"
            assert key_with_notify_only in result[2].status_extended

    def test_rotation_action_not_first_in_lifetime_actions(self):
        keyvault_client = mock.MagicMock
        keyvault_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        keyvault_name = "keyvault_name"
        key_name = "key_name"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.keyvault.keyvault_key_rotation_enabled.keyvault_key_rotation_enabled.keyvault_client",
                new=keyvault_client,
            ),
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
                                            action="Notify",
                                            lifetime_action_type="Notify",
                                            lifetime_percentage=90,
                                        ),
                                        KeyRotationLifetimeAction(
                                            action="Rotate",
                                            lifetime_action_type="Rotate",
                                            lifetime_percentage=80,
                                        ),
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
                == f"Key {key_name} in Key Vault {keyvault_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} has a rotation policy set."
            )
