from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_keyvault_access_only_through_private_endpoints:
    def test_no_key_vaults(self):
        keyvault_client = mock.MagicMock
        keyvault_client.key_vaults = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.keyvault.keyvault_access_only_through_private_endpoints.keyvault_access_only_through_private_endpoints.keyvault_client",
                new=keyvault_client,
            ),
        ):
            from prowler.providers.azure.services.keyvault.keyvault_access_only_through_private_endpoints.keyvault_access_only_through_private_endpoints import (
                keyvault_access_only_through_private_endpoints,
            )

            check = keyvault_access_only_through_private_endpoints()
            result = check.execute()
            assert len(result) == 0

    def test_key_vaults_no_private_endpoints(self):
        keyvault_client = mock.MagicMock
        keyvault_name = "Keyvault Name"
        keyvault_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.keyvault.keyvault_access_only_through_private_endpoints.keyvault_access_only_through_private_endpoints.keyvault_client",
                new=keyvault_client,
            ),
        ):
            from prowler.providers.azure.services.keyvault.keyvault_access_only_through_private_endpoints.keyvault_access_only_through_private_endpoints import (
                keyvault_access_only_through_private_endpoints,
            )
            from prowler.providers.azure.services.keyvault.keyvault_service import (
                KeyVaultInfo,
                VaultProperties,
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
                            enable_rbac_authorization=False,
                            private_endpoint_connections=[],
                            enable_soft_delete=True,
                            enable_purge_protection=True,
                            public_network_access_disabled=False,
                        ),
                    )
                ]
            }

            check = keyvault_access_only_through_private_endpoints()
            result = check.execute()
            assert len(result) == 0

    def test_key_vaults_with_private_endpoints_public_access_enabled(self):
        keyvault_client = mock.MagicMock
        keyvault_name = "Keyvault Name"
        keyvault_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.keyvault.keyvault_access_only_through_private_endpoints.keyvault_access_only_through_private_endpoints.keyvault_client",
                new=keyvault_client,
            ),
        ):
            from prowler.providers.azure.services.keyvault.keyvault_access_only_through_private_endpoints.keyvault_access_only_through_private_endpoints import (
                keyvault_access_only_through_private_endpoints,
            )
            from prowler.providers.azure.services.keyvault.keyvault_service import (
                KeyVaultInfo,
                PrivateEndpointConnection,
                VaultProperties,
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
                            enable_rbac_authorization=True,
                            private_endpoint_connections=[
                                PrivateEndpointConnection(id="id1")
                            ],
                            enable_soft_delete=True,
                            enable_purge_protection=True,
                            public_network_access_disabled=False,
                        ),
                    )
                ]
            }

            check = keyvault_access_only_through_private_endpoints()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Keyvault {keyvault_name} from subscription {AZURE_SUBSCRIPTION_ID} has public network access enabled while using private endpoints."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == keyvault_name
            assert result[0].resource_id == keyvault_id
            assert result[0].location == "westeurope"

    def test_key_vaults_with_private_endpoints_public_access_disabled(self):
        keyvault_client = mock.MagicMock
        keyvault_name = "Keyvault Name"
        keyvault_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.keyvault.keyvault_access_only_through_private_endpoints.keyvault_access_only_through_private_endpoints.keyvault_client",
                new=keyvault_client,
            ),
        ):
            from prowler.providers.azure.services.keyvault.keyvault_access_only_through_private_endpoints.keyvault_access_only_through_private_endpoints import (
                keyvault_access_only_through_private_endpoints,
            )
            from prowler.providers.azure.services.keyvault.keyvault_service import (
                KeyVaultInfo,
                PrivateEndpointConnection,
                VaultProperties,
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
                            enable_rbac_authorization=True,
                            private_endpoint_connections=[
                                PrivateEndpointConnection(id="id1")
                            ],
                            enable_soft_delete=True,
                            enable_purge_protection=True,
                            public_network_access_disabled=True,
                        ),
                    )
                ]
            }

            check = keyvault_access_only_through_private_endpoints()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Keyvault {keyvault_name} from subscription {AZURE_SUBSCRIPTION_ID} has public network access disabled and is using private endpoints."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == keyvault_name
            assert result[0].resource_id == keyvault_id
            assert result[0].location == "westeurope"
