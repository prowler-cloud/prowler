from unittest import mock
from unittest.mock import MagicMock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class TestContainerRegistryAdminUserDisabled:
    def test_no_container_registries(self):
        containerregistry_client = MagicMock()
        containerregistry_client.registries = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.containerregistry.containerregistry_admin_user_disabled.containerregistry_admin_user_disabled.containerregistry_client",
            new=containerregistry_client,
        ):
            from prowler.providers.azure.services.containerregistry.containerregistry_admin_user_disabled.containerregistry_admin_user_disabled import (
                containerregistry_admin_user_disabled,
            )

            check = containerregistry_admin_user_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_container_registry_admin_user_enabled(self):
        containerregistry_client = MagicMock()
        registry_id = str(uuid4())

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.containerregistry.containerregistry_admin_user_disabled.containerregistry_admin_user_disabled.containerregistry_client",
            new=containerregistry_client,
        ):
            from prowler.providers.azure.services.containerregistry.containerregistry_admin_user_disabled.containerregistry_admin_user_disabled import (
                containerregistry_admin_user_disabled,
            )
            from prowler.providers.azure.services.containerregistry.containerregistry_service import (
                ContainerRegistryInfo,
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
                        network_rule_set=None,
                        monitor_diagnostic_settings=[],
                        private_endpoint_connections=[],
                    )
                }
            }

            check = containerregistry_admin_user_disabled()

            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Container Registry mock_registry from subscription {AZURE_SUBSCRIPTION_ID} has its admin user enabled."
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

    def test_container_registry_admin_user_disabled(self):
        containerregistry_client = mock.MagicMock()
        containerregistry_client.registries = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.containerregistry.containerregistry_admin_user_disabled.containerregistry_admin_user_disabled.containerregistry_client",
            new=containerregistry_client,
        ):
            from prowler.providers.azure.services.containerregistry.containerregistry_admin_user_disabled.containerregistry_admin_user_disabled import (
                containerregistry_admin_user_disabled,
            )
            from prowler.providers.azure.services.containerregistry.containerregistry_service import (
                ContainerRegistryInfo,
            )

            registry_id = "mock_registry_id"

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
                        network_rule_set=None,
                        monitor_diagnostic_settings=[],
                        private_endpoint_connections=[],
                    )
                }
            }

            check = containerregistry_admin_user_disabled()

            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Container Registry mock_registry from subscription {AZURE_SUBSCRIPTION_ID} has its admin user disabled."
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
