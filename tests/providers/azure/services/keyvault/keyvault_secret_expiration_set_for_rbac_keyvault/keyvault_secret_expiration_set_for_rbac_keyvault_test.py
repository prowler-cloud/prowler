from unittest import mock
from uuid import uuid4

from azure.mgmt.keyvault.v2023_07_01.models import SecretAttributes, VaultProperties

from prowler.providers.azure.services.keyvault.keyvault_service import (
    KeyVaultInfo,
    Secret,
)

AZURE_SUBSCRIPTION = str(uuid4())


class Test_keyvault_secret_expiration_set_for_rbac_keyvault:
    def test_no_key_vaults(self):
        keyvault_client = mock.MagicMock
        keyvault_client.key_vaults = {}

        with mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_secret_expiration_set_for_rbac_keyvault.keyvault_secret_expiration_set_for_rbac_keyvault.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_secret_expiration_set_for_rbac_keyvault.keyvault_secret_expiration_set_for_rbac_keyvault import (
                keyvault_secret_expiration_set_for_rbac_keyvault,
            )

            check = keyvault_secret_expiration_set_for_rbac_keyvault()
            result = check.execute()
            assert len(result) == 0

    def test_no_secrets(self):
        keyvault_client = mock.MagicMock
        keyvault_client.key_vaults = {
            AZURE_SUBSCRIPTION: [
                KeyVaultInfo(
                    id="id",
                    name="name",
                    location="location",
                    resource_group="resource_group",
                    properties=VaultProperties(
                        tenant_id="tenantid", sku="sku", enable_rbac_authorization=True
                    ),
                    keys=[],
                    secrets=[],
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_secret_expiration_set_for_rbac_keyvault.keyvault_secret_expiration_set_for_rbac_keyvault.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_secret_expiration_set_for_rbac_keyvault.keyvault_secret_expiration_set_for_rbac_keyvault import (
                keyvault_secret_expiration_set_for_rbac_keyvault,
            )

            check = keyvault_secret_expiration_set_for_rbac_keyvault()
            result = check.execute()
            assert len(result) == 0

    def test_key_vaults_invalid_secrets(self):
        keyvault_client = mock.MagicMock
        keyvault_name = "Keyvault Name"
        keyvault_id = str(uuid4())
        secret = Secret(
            id="id",
            name="name",
            enabled=True,
            location="location",
            attributes=SecretAttributes(expires=None, enabled=True),
        )
        keyvault_client.key_vaults = {
            AZURE_SUBSCRIPTION: [
                KeyVaultInfo(
                    id=keyvault_id,
                    name=keyvault_name,
                    location="location",
                    resource_group="resource_group",
                    properties=VaultProperties(
                        tenant_id="tenantid", sku="sku", enable_rbac_authorization=True
                    ),
                    keys=[],
                    secrets=[secret],
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_secret_expiration_set_for_rbac_keyvault.keyvault_secret_expiration_set_for_rbac_keyvault.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_secret_expiration_set_for_rbac_keyvault.keyvault_secret_expiration_set_for_rbac_keyvault import (
                keyvault_secret_expiration_set_for_rbac_keyvault,
            )

            check = keyvault_secret_expiration_set_for_rbac_keyvault()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Keyvault {keyvault_name} from subscription {AZURE_SUBSCRIPTION} has a secret without expiration date set."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == keyvault_name
            assert result[0].resource_id == keyvault_id

    def test_key_vaults_invalid_multiple_secrets(self):
        keyvault_client = mock.MagicMock
        keyvault_name = "Keyvault Name"
        keyvault_id = str(uuid4())
        secret1 = Secret(
            id="id",
            name="name",
            enabled=True,
            location="location",
            attributes=SecretAttributes(expires=None, enabled=True),
        )
        secret2 = Secret(
            id="id",
            name="name",
            enabled=True,
            location="location",
            attributes=SecretAttributes(expires=84934, enabled=True),
        )
        keyvault_client.key_vaults = {
            AZURE_SUBSCRIPTION: [
                KeyVaultInfo(
                    id=keyvault_id,
                    name=keyvault_name,
                    location="location",
                    resource_group="resource_group",
                    properties=VaultProperties(
                        tenant_id="tenantid", sku="sku", enable_rbac_authorization=True
                    ),
                    keys=[],
                    secrets=[secret1, secret2],
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_secret_expiration_set_for_rbac_keyvault.keyvault_secret_expiration_set_for_rbac_keyvault.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_secret_expiration_set_for_rbac_keyvault.keyvault_secret_expiration_set_for_rbac_keyvault import (
                keyvault_secret_expiration_set_for_rbac_keyvault,
            )

            check = keyvault_secret_expiration_set_for_rbac_keyvault()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Keyvault {keyvault_name} from subscription {AZURE_SUBSCRIPTION} has a secret without expiration date set."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == keyvault_name
            assert result[0].resource_id == keyvault_id

    def test_key_vaults_valid_keys(self):
        keyvault_client = mock.MagicMock
        keyvault_name = "Keyvault Name"
        keyvault_id = str(uuid4())
        secret = Secret(
            id="id",
            name="name",
            enabled=True,
            location="location",
            attributes=SecretAttributes(expires=None, enabled=False),
        )
        keyvault_client.key_vaults = {
            AZURE_SUBSCRIPTION: [
                KeyVaultInfo(
                    id=keyvault_id,
                    name=keyvault_name,
                    location="location",
                    resource_group="resource_group",
                    properties=VaultProperties(
                        tenant_id="tenantid", sku="sku", enable_rbac_authorization=True
                    ),
                    keys=[],
                    secrets=[secret],
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_secret_expiration_set_for_rbac_keyvault.keyvault_secret_expiration_set_for_rbac_keyvault.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_secret_expiration_set_for_rbac_keyvault.keyvault_secret_expiration_set_for_rbac_keyvault import (
                keyvault_secret_expiration_set_for_rbac_keyvault,
            )

            check = keyvault_secret_expiration_set_for_rbac_keyvault()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Keyvault {keyvault_name} from subscription {AZURE_SUBSCRIPTION} has all the secrets with expiration date set."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == keyvault_name
            assert result[0].resource_id == keyvault_id
