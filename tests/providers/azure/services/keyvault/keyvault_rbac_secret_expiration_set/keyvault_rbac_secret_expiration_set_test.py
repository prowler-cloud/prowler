from unittest import mock
from uuid import uuid4

from azure.mgmt.keyvault.v2023_07_01.models import SecretAttributes, VaultProperties

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_keyvault_rbac_secret_expiration_set:
    def test_no_key_vaults(self):
        keyvault_client = mock.MagicMock
        keyvault_client.key_vaults = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_rbac_secret_expiration_set.keyvault_rbac_secret_expiration_set.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_rbac_secret_expiration_set.keyvault_rbac_secret_expiration_set import (
                keyvault_rbac_secret_expiration_set,
            )

            check = keyvault_rbac_secret_expiration_set()
            result = check.execute()
            assert len(result) == 0

    def test_no_secrets(self):
        keyvault_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_rbac_secret_expiration_set.keyvault_rbac_secret_expiration_set.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_rbac_secret_expiration_set.keyvault_rbac_secret_expiration_set import (
                keyvault_rbac_secret_expiration_set,
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
            check = keyvault_rbac_secret_expiration_set()
            result = check.execute()
            assert len(result) == 0

    def test_key_vaults_invalid_secrets(self):
        keyvault_client = mock.MagicMock
        keyvault_name = "Keyvault Name"
        keyvault_id = str(uuid4())
        secret_name = "Secret"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_rbac_secret_expiration_set.keyvault_rbac_secret_expiration_set.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_rbac_secret_expiration_set.keyvault_rbac_secret_expiration_set import (
                keyvault_rbac_secret_expiration_set,
            )
            from prowler.providers.azure.services.keyvault.keyvault_service import (
                KeyVaultInfo,
                Secret,
            )

            secret = Secret(
                id="id",
                name=secret_name,
                enabled=True,
                location="location",
                attributes=SecretAttributes(expires=None),
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
                        keys=[],
                        secrets=[secret],
                    )
                ]
            }
            check = keyvault_rbac_secret_expiration_set()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Keyvault {keyvault_name} from subscription {AZURE_SUBSCRIPTION_ID} has the secret {secret_name} without expiration date set."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == keyvault_name
            assert result[0].resource_id == keyvault_id
            assert result[0].location == "westeurope"

    def test_key_vaults_invalid_multiple_secrets(self):
        keyvault_client = mock.MagicMock
        keyvault_name = "Keyvault Name"
        keyvault_id = str(uuid4())
        secret1_name = "Secret1"
        secret2_name = "Secret2"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_rbac_secret_expiration_set.keyvault_rbac_secret_expiration_set.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_rbac_secret_expiration_set.keyvault_rbac_secret_expiration_set import (
                keyvault_rbac_secret_expiration_set,
            )
            from prowler.providers.azure.services.keyvault.keyvault_service import (
                KeyVaultInfo,
                Secret,
            )

            secret1 = Secret(
                id="id",
                name=secret1_name,
                enabled=True,
                location="location",
                attributes=SecretAttributes(expires=None),
            )
            secret2 = Secret(
                id="id",
                name=secret2_name,
                enabled=True,
                location="location",
                attributes=SecretAttributes(expires=84934),
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
                        keys=[],
                        secrets=[secret1, secret2],
                    )
                ]
            }
            check = keyvault_rbac_secret_expiration_set()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Keyvault {keyvault_name} from subscription {AZURE_SUBSCRIPTION_ID} has the secret {secret1_name} without expiration date set."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == keyvault_name
            assert result[0].resource_id == keyvault_id
            assert result[0].location == "westeurope"

    def test_key_vaults_valid_keys(self):
        keyvault_client = mock.MagicMock
        keyvault_name = "Keyvault Name"
        keyvault_id = str(uuid4())

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_rbac_secret_expiration_set.keyvault_rbac_secret_expiration_set.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_rbac_secret_expiration_set.keyvault_rbac_secret_expiration_set import (
                keyvault_rbac_secret_expiration_set,
            )
            from prowler.providers.azure.services.keyvault.keyvault_service import (
                KeyVaultInfo,
                Secret,
            )

            secret = Secret(
                id="id",
                name="name",
                enabled=False,
                location="location",
                attributes=SecretAttributes(expires=None),
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
                        keys=[],
                        secrets=[secret],
                    )
                ]
            }
            check = keyvault_rbac_secret_expiration_set()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Keyvault {keyvault_name} from subscription {AZURE_SUBSCRIPTION_ID} has all the secrets with expiration date set."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == keyvault_name
            assert result[0].resource_id == keyvault_id
            assert result[0].location == "westeurope"
