from unittest import mock
from unittest.mock import MagicMock
from uuid import uuid4

from azure.mgmt.containerregistry.models import (
    PrivateEndpoint,
    PrivateEndpointConnection,
    PrivateLinkServiceConnectionState,
)

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_containerregistry_uses_private_link:
    def test_no_container_registries(self):
        containerregistry_client = MagicMock()
        containerregistry_client.registries = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.containerregistry.containerregistry_uses_private_link.containerregistry_uses_private_link.containerregistry_client",
            new=containerregistry_client,
        ):
            from prowler.providers.azure.services.containerregistry.containerregistry_uses_private_link.containerregistry_uses_private_link import (
                containerregistry_uses_private_link,
            )

            check = containerregistry_uses_private_link()
            result = check.execute()
            assert len(result) == 0

    def test_container_registry_not_uses_private_link(self):
        containerregistry_client = MagicMock()
        registry_id = str(uuid4())

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.containerregistry.containerregistry_uses_private_link.containerregistry_uses_private_link.containerregistry_client",
            new=containerregistry_client,
        ):
            from prowler.providers.azure.services.containerregistry.containerregistry_service import (
                ContainerRegistryInfo,
            )
            from prowler.providers.azure.services.containerregistry.containerregistry_uses_private_link.containerregistry_uses_private_link import (
                containerregistry_uses_private_link,
            )

            containerregistry_client.registries = {
                AZURE_SUBSCRIPTION_ID: {
                    registry_id: ContainerRegistryInfo(
                        id=registry_id,
                        name="mock_registry",
                        location="westeurope",
                        resource_group="mock_resource_group",
                        sku="Basic",
                        login_server="mock_login_server.azurecr.io",
                        public_network_access="Enabled",
                        admin_user_enabled=True,
                        monitor_diagnostic_settings=[],
                        network_rule_set=[],
                        private_endpoint_connections=[],
                    )
                }
            }

            check = containerregistry_uses_private_link()

            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Container Registry mock_registry from subscription {AZURE_SUBSCRIPTION_ID} does not use a private link."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "mock_registry"
            assert (
                result[0].resource_id
                == containerregistry_client.registries[AZURE_SUBSCRIPTION_ID][
                    registry_id
                ].id
            )
            assert result[0].location == "westeurope"

    def test_container_registry_uses_private_link(self):
        containerregistry_client = mock.MagicMock()
        containerregistry_client.registries = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.containerregistry.containerregistry_uses_private_link.containerregistry_uses_private_link.containerregistry_client",
            new=containerregistry_client,
        ):
            from prowler.providers.azure.services.containerregistry.containerregistry_service import (
                ContainerRegistryInfo,
            )
            from prowler.providers.azure.services.containerregistry.containerregistry_uses_private_link.containerregistry_uses_private_link import (
                containerregistry_uses_private_link,
            )

            registry_id = str(uuid4())

            containerregistry_client.registries = {
                AZURE_SUBSCRIPTION_ID: {
                    registry_id: ContainerRegistryInfo(
                        id=registry_id,
                        name="mock_registry",
                        location="westeurope",
                        resource_group="mock_resource_group",
                        sku="Basic",
                        login_server="mock_login_server.azurecr.io",
                        public_network_access="Enabled",
                        admin_user_enabled=False,
                        monitor_diagnostic_settings=[],
                        network_rule_set=[],
                        private_endpoint_connections=[
                            PrivateEndpointConnection(
                                id="/subscriptions/AZURE_SUBSCRIPTION_ID/resourceGroups/mock_resource_group/providers/Microsoft.ContainerRegistry/registries/mock_registry/privateEndpointConnections/myConnection",
                                private_endpoint=PrivateEndpoint(
                                    id="/subscriptions/AZURE_SUBSCRIPTION_ID/resourceGroups/mock_resource_group/providers/Microsoft.Network/privateEndpoints/myPrivateEndpoint"
                                ),
                                private_link_service_connection_state=PrivateLinkServiceConnectionState(
                                    status="Approved",
                                    description="Auto-approved connection",
                                    actions_required="None",
                                ),
                                provisioning_state="Succeeded",
                            )
                        ],
                    )
                }
            }

            check = containerregistry_uses_private_link()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Container Registry mock_registry from subscription {AZURE_SUBSCRIPTION_ID} uses a private link."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "mock_registry"
            assert (
                result[0].resource_id
                == containerregistry_client.registries[AZURE_SUBSCRIPTION_ID][
                    registry_id
                ].id
            )
            assert result[0].location == "westeurope"
