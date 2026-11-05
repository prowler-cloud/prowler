from unittest.mock import MagicMock, patch
from uuid import uuid4

from azure.mgmt.containerregistry.v2023_11_01_preview.models import Registry, Sku

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    RESOURCE_GROUP,
    RESOURCE_GROUP_LIST,
    set_mocked_azure_provider,
)


class TestContainerRegistryService:
    def test_get_client_uses_api_version_with_network_properties(self):
        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            patch(
                "prowler.providers.azure.services.monitor.monitor_service.Monitor",
                new=MagicMock(),
            ),
            patch(
                "prowler.providers.azure.services.containerregistry.containerregistry_service.ContainerRegistry._get_container_registries",
                return_value={},
            ),
        ):
            from prowler.providers.azure.services.containerregistry.containerregistry_service import (
                ContainerRegistry,
            )

            containerregistry_service = ContainerRegistry(set_mocked_azure_provider())

        assert (
            containerregistry_service.clients[
                AZURE_SUBSCRIPTION_ID
            ].registries._api_version
            == "2023-11-01-preview"
        )

    def test_get_container_registry(self):
        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            patch(
                "prowler.providers.azure.services.monitor.monitor_service.Monitor",
                new=MagicMock(),
            ),
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


class Test_ContainerRegistry_get_registries:
    @staticmethod
    def _create_service(mock_client):
        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            patch(
                "prowler.providers.azure.services.monitor.monitor_service.Monitor",
                new=MagicMock(),
            ),
            patch(
                "prowler.providers.azure.services.containerregistry.containerregistry_service.ContainerRegistry._get_container_registries",
                return_value={},
            ),
        ):
            from prowler.providers.azure.services.containerregistry.containerregistry_service import (
                ContainerRegistry,
            )

            containerregistry_service = ContainerRegistry(set_mocked_azure_provider())

        containerregistry_service.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        containerregistry_service.resource_groups = None
        return containerregistry_service

    def test_get_container_registries_maps_network_properties(self):
        registry_id = (
            f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}"
            "/providers/Microsoft.ContainerRegistry/registries/mock-registry"
        )
        registry = Registry(
            location="westeurope",
            sku=Sku(name="Premium"),
            public_network_access="Disabled",
        )
        registry.id = registry_id
        registry.name = "mock-registry"
        registry.login_server = "mock-registry.azurecr.io"

        private_endpoint_connection = MagicMock()
        private_endpoint_connection.id = (
            f"{registry_id}/privateEndpointConnections/pec-1"
        )
        private_endpoint_connection.name = "pec-1"
        private_endpoint_connection.type = (
            "Microsoft.ContainerRegistry/registries/privateEndpointConnections"
        )
        registry.private_endpoint_connections = [private_endpoint_connection]

        mock_client = MagicMock()
        mock_client.registries.list.return_value = [registry]
        containerregistry_service = self._create_service(mock_client)

        with patch.object(
            containerregistry_service,
            "_get_registry_monitor_settings",
            return_value=[],
        ):
            result = containerregistry_service._get_container_registries()

        registry_info = result[AZURE_SUBSCRIPTION_ID][registry_id]
        assert not registry_info.public_network_access
        assert len(registry_info.private_endpoint_connections) == 1
        assert registry_info.private_endpoint_connections[0].id == (
            private_endpoint_connection.id
        )

    def test_get_container_registries_without_private_endpoints(self):
        registry_id = (
            f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}"
            "/providers/Microsoft.ContainerRegistry/registries/public-registry"
        )
        registry = Registry(
            location="westeurope",
            sku=Sku(name="Basic"),
            public_network_access="Enabled",
        )
        registry.id = registry_id
        registry.name = "public-registry"
        registry.login_server = "public-registry.azurecr.io"

        mock_client = MagicMock()
        mock_client.registries.list.return_value = [registry]
        containerregistry_service = self._create_service(mock_client)

        with patch.object(
            containerregistry_service,
            "_get_registry_monitor_settings",
            return_value=[],
        ):
            result = containerregistry_service._get_container_registries()

        registry_info = result[AZURE_SUBSCRIPTION_ID][registry_id]
        assert registry_info.public_network_access
        assert registry_info.private_endpoint_connections == []

    def test_get_container_registries_no_resource_groups(self):
        mock_client = MagicMock()
        mock_client.registries.list.return_value = []

        mock_provider = MagicMock()
        mock_provider.identity = MagicMock()
        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.azure.services.monitor.monitor_service.Monitor",
                new=MagicMock(),
            ),
            patch(
                "prowler.providers.azure.services.containerregistry.containerregistry_service.ContainerRegistry._get_container_registries",
                return_value={},
            ),
        ):
            from prowler.providers.azure.services.containerregistry.containerregistry_service import (
                ContainerRegistry,
            )

            cr = ContainerRegistry(set_mocked_azure_provider())

        cr.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        cr.resource_groups = None

        with patch(
            "prowler.providers.azure.services.containerregistry.containerregistry_service.monitor_client"
        ):
            result = cr._get_container_registries()

        mock_client.registries.list.assert_called_once()
        mock_client.registries.list_by_resource_group.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_container_registries_with_resource_group(self):
        mock_client = MagicMock()
        mock_client.registries.list_by_resource_group.return_value = []

        mock_provider = MagicMock()
        mock_provider.identity = MagicMock()
        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.azure.services.monitor.monitor_service.Monitor",
                new=MagicMock(),
            ),
            patch(
                "prowler.providers.azure.services.containerregistry.containerregistry_service.ContainerRegistry._get_container_registries",
                return_value={},
            ),
        ):
            from prowler.providers.azure.services.containerregistry.containerregistry_service import (
                ContainerRegistry,
            )

            cr = ContainerRegistry(set_mocked_azure_provider())

        cr.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        cr.resource_groups = {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}

        with patch(
            "prowler.providers.azure.services.containerregistry.containerregistry_service.monitor_client"
        ):
            result = cr._get_container_registries()

        mock_client.registries.list_by_resource_group.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP
        )
        mock_client.registries.list.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_container_registries_empty_resource_group_for_subscription(self):
        mock_client = MagicMock()

        mock_provider = MagicMock()
        mock_provider.identity = MagicMock()
        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.azure.services.monitor.monitor_service.Monitor",
                new=MagicMock(),
            ),
            patch(
                "prowler.providers.azure.services.containerregistry.containerregistry_service.ContainerRegistry._get_container_registries",
                return_value={},
            ),
        ):
            from prowler.providers.azure.services.containerregistry.containerregistry_service import (
                ContainerRegistry,
            )

            cr = ContainerRegistry(set_mocked_azure_provider())

        cr.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        cr.resource_groups = {AZURE_SUBSCRIPTION_ID: []}

        with patch(
            "prowler.providers.azure.services.containerregistry.containerregistry_service.monitor_client"
        ):
            result = cr._get_container_registries()

        mock_client.registries.list_by_resource_group.assert_not_called()
        mock_client.registries.list.assert_not_called()
        assert result[AZURE_SUBSCRIPTION_ID] == {}

    def test_get_container_registries_with_multiple_resource_groups(self):
        mock_client = MagicMock()
        mock_client.registries.list_by_resource_group.return_value = []

        mock_provider = MagicMock()
        mock_provider.identity = MagicMock()
        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.azure.services.monitor.monitor_service.Monitor",
                new=MagicMock(),
            ),
            patch(
                "prowler.providers.azure.services.containerregistry.containerregistry_service.ContainerRegistry._get_container_registries",
                return_value={},
            ),
        ):
            from prowler.providers.azure.services.containerregistry.containerregistry_service import (
                ContainerRegistry,
            )

            cr = ContainerRegistry(set_mocked_azure_provider())

        cr.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        cr.resource_groups = {AZURE_SUBSCRIPTION_ID: RESOURCE_GROUP_LIST}

        with patch(
            "prowler.providers.azure.services.containerregistry.containerregistry_service.monitor_client"
        ):
            result = cr._get_container_registries()

        assert mock_client.registries.list_by_resource_group.call_count == len(
            RESOURCE_GROUP_LIST
        )
        mock_client.registries.list.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_container_registries_with_mixed_case_resource_group(self):
        mock_client = MagicMock()
        mock_client.registries.list_by_resource_group.return_value = []

        mock_provider = MagicMock()
        mock_provider.identity = MagicMock()
        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.azure.services.monitor.monitor_service.Monitor",
                new=MagicMock(),
            ),
            patch(
                "prowler.providers.azure.services.containerregistry.containerregistry_service.ContainerRegistry._get_container_registries",
                return_value={},
            ),
        ):
            from prowler.providers.azure.services.containerregistry.containerregistry_service import (
                ContainerRegistry,
            )

            cr = ContainerRegistry(set_mocked_azure_provider())

        cr.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        cr.resource_groups = {AZURE_SUBSCRIPTION_ID: ["MyRegistry-RG"]}

        with patch(
            "prowler.providers.azure.services.containerregistry.containerregistry_service.monitor_client"
        ):
            cr._get_container_registries()

        mock_client.registries.list_by_resource_group.assert_called_once_with(
            resource_group_name="MyRegistry-RG"
        )
