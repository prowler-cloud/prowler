from unittest.mock import MagicMock, patch
from uuid import uuid4

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class TestContainerRegistryService:
    def test_get_container_registry(self):
        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), patch(
            "prowler.providers.azure.services.monitor.monitor_service.Monitor",
            new=MagicMock(),
        ):
            from prowler.providers.azure.services.containerregistry.containerregistry_service import (
                ContainerRegistryInfo,
            )

            # Initialize ContainerRegistry with the mocked provider
            containerregistry_service = MagicMock()
            registry_id = str(uuid4())
            containerregistry_service.registries = {
                AZURE_SUBSCRIPTION_ID: {
                    registry_id: ContainerRegistryInfo(
                        id=registry_id,
                        name="mock_registry",
                        location="westeurope",
                        resource_group="mock_resource_group",
                        sku="Basic",
                        login_server="mock_login_server.azurecr.io",
                        public_network_access=False,
                        admin_user_enabled=True,
                        network_rule_set=None,
                        private_endpoint_connections=[],
                        monitor_diagnostic_settings=[
                            {
                                "id": "id1/id1",
                                "logs": [
                                    {
                                        "category": "ContainerLogs",
                                        "enabled": True,
                                    },
                                    {
                                        "category": "AdminLogs",
                                        "enabled": False,
                                    },
                                ],
                                "storage_account_name": "mock_storage_account",
                                "storage_account_id": "mock_storage_account_id",
                                "name": "mock_diagnostic_setting",
                            }
                        ],
                    )
                }
            }

            # Assertions to check the populated data in the registries
            assert len(containerregistry_service.registries[AZURE_SUBSCRIPTION_ID]) == 1

            registry_info = containerregistry_service.registries[AZURE_SUBSCRIPTION_ID][
                registry_id
            ]

            assert registry_info.id == registry_id
            assert registry_info.name == "mock_registry"
            assert registry_info.location == "westeurope"
            assert registry_info.resource_group == "mock_resource_group"
            assert registry_info.sku == "Basic"
            assert registry_info.login_server == "mock_login_server.azurecr.io"
            assert not registry_info.public_network_access
            assert registry_info.admin_user_enabled is True
            assert isinstance(registry_info.monitor_diagnostic_settings, list)

            # Check the properties of monitor diagnostic settings
            monitor_setting = registry_info.monitor_diagnostic_settings[0]
            assert monitor_setting["id"] == "id1/id1"  # Use dictionary access here
            assert monitor_setting["storage_account_name"] == "mock_storage_account"
            assert monitor_setting["storage_account_id"] == "mock_storage_account_id"
            assert monitor_setting["name"] == "mock_diagnostic_setting"
            assert len(monitor_setting["logs"]) == 2

            assert monitor_setting["logs"][0]["category"] == "ContainerLogs"
            assert monitor_setting["logs"][0]["enabled"] is True
            assert monitor_setting["logs"][1]["category"] == "AdminLogs"
            assert monitor_setting["logs"][1]["enabled"] is False
