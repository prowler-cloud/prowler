from unittest import mock
from uuid import uuid4

from azure.mgmt.keyvault.v2023_07_01.models import VaultProperties

from prowler.providers.azure.services.keyvault.keyvault_service import KeyVaultInfo
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_provider,
)


class Test_keyvault_rbac_enabled:
    def test_no_key_vaults(self):
        keyvault_client = mock.MagicMock
        keyvault_client.key_vaults = {}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_rbac_enabled.keyvault_rbac_enabled.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_rbac_enabled.keyvault_rbac_enabled import (
                keyvault_rbac_enabled,
            )

            check = keyvault_rbac_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_key_vaults_no_rbac(self):
        keyvault_client = mock.MagicMock
        keyvault_name = "Keyvault Name"
        keyvault_id = str(uuid4())
        keyvault_client.key_vaults = {
            AZURE_SUBSCRIPTION: [
                KeyVaultInfo(
                    id=keyvault_id,
                    name=keyvault_name,
                    location="location",
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

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_rbac_enabled.keyvault_rbac_enabled.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_rbac_enabled.keyvault_rbac_enabled import (
                keyvault_rbac_enabled,
            )

            check = keyvault_rbac_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Keyvault {keyvault_name} from subscription {AZURE_SUBSCRIPTION} is not using RBAC for access control."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == keyvault_name
            assert result[0].resource_id == keyvault_id

    def test_key_vaults_rbac(self):
        keyvault_client = mock.MagicMock
        keyvault_name = "Keyvault Name"
        keyvault_id = str(uuid4())
        keyvault_client.key_vaults = {
            AZURE_SUBSCRIPTION: [
                KeyVaultInfo(
                    id=keyvault_id,
                    name=keyvault_name,
                    location="location",
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

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_rbac_enabled.keyvault_rbac_enabled.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_rbac_enabled.keyvault_rbac_enabled import (
                keyvault_rbac_enabled,
            )

            check = keyvault_rbac_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Keyvault {keyvault_name} from subscription {AZURE_SUBSCRIPTION} is using RBAC for access control."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == keyvault_name
            assert result[0].resource_id == keyvault_id
