from unittest import mock
from uuid import uuid4

from azure.mgmt.keyvault.v2023_07_01.models import SecretAttributes, VaultProperties

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_keyvault_recoverable:

    def test_no_key_vaults(self):
        keyvault_client = mock.MagicMock
        keyvault_client.key_vaults = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_recoverable.keyvault_recoverable.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_recoverable.keyvault_recoverable import (
                keyvault_recoverable,
            )

            check = keyvault_recoverable()
            result = check.execute()
            assert len(result) == 0

    def test_key_vaults_no_purge(self):
        keyvault_client = mock.MagicMock
        keyvault_name = "Keyvault Name"
        keyvault_id = str(uuid4())

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_recoverable.keyvault_recoverable.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_recoverable.keyvault_recoverable import (
                keyvault_recoverable,
            )
            from prowler.providers.azure.services.keyvault.keyvault_service import (
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
                            enable_soft_delete=True,
                            enable_purge_protection=False,
                        ),
                        keys=[],
                        secrets=[],
                    )
                ]
            }
            check = keyvault_recoverable()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Keyvault {keyvault_name} from subscription {AZURE_SUBSCRIPTION_ID} is not recoverable."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == keyvault_name
            assert result[0].resource_id == keyvault_id
            assert result[0].location == "westeurope"

    def test_key_vaults_no_soft_delete(self):
        keyvault_client = mock.MagicMock
        keyvault_name = "Keyvault Name"
        keyvault_id = str(uuid4())

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_recoverable.keyvault_recoverable.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_recoverable.keyvault_recoverable import (
                keyvault_recoverable,
            )
            from prowler.providers.azure.services.keyvault.keyvault_service import (
                KeyVaultInfo,
                Secret,
            )

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
                            enable_soft_delete=True,
                            enable_purge_protection=False,
                        ),
                        keys=[],
                        secrets=[secret1, secret2],
                    )
                ]
            }
            check = keyvault_recoverable()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Keyvault {keyvault_name} from subscription {AZURE_SUBSCRIPTION_ID} is not recoverable."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == keyvault_name
            assert result[0].resource_id == keyvault_id
            assert result[0].location == "westeurope"

    def test_key_vaults_valid_configuration(self):
        keyvault_client = mock.MagicMock
        keyvault_name = "Keyvault Name"
        keyvault_id = str(uuid4())

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_recoverable.keyvault_recoverable.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_recoverable.keyvault_recoverable import (
                keyvault_recoverable,
            )
            from prowler.providers.azure.services.keyvault.keyvault_service import (
                KeyVaultInfo,
                Secret,
            )

            secret = Secret(
                id="id",
                name="name",
                enabled=True,
                location="location",
                attributes=SecretAttributes(expires=None, enabled=False),
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
                            enable_soft_delete=True,
                            enable_purge_protection=True,
                        ),
                        keys=[],
                        secrets=[secret],
                    )
                ]
            }
            check = keyvault_recoverable()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Keyvault {keyvault_name} from subscription {AZURE_SUBSCRIPTION_ID} is recoverable."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == keyvault_name
            assert result[0].resource_id == keyvault_id
            assert result[0].location == "westeurope"
