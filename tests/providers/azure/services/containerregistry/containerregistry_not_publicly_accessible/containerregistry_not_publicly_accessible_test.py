from unittest import mock
from unittest.mock import MagicMock
from uuid import uuid4

from azure.mgmt.containerregistry.models import NetworkRuleSet

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_containerregistry_not_publicly_accessible:
    def test_no_container_registries(self):
        containerregistry_client = MagicMock()
        containerregistry_client.registries = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.containerregistry.containerregistry_not_publicly_accessible.containerregistry_not_publicly_accessible.containerregistry_client",
            new=containerregistry_client,
        ):
            from prowler.providers.azure.services.containerregistry.containerregistry_not_publicly_accessible.containerregistry_not_publicly_accessible import (
                containerregistry_not_publicly_accessible,
            )

            check = containerregistry_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 0

    def test_container_registry_network_access_unrestricted(self):
        containerregistry_client = MagicMock()
        registry_id = str(uuid4())

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.containerregistry.containerregistry_not_publicly_accessible.containerregistry_not_publicly_accessible.containerregistry_client",
            new=containerregistry_client,
        ):
            from prowler.providers.azure.services.containerregistry.containerregistry_not_publicly_accessible.containerregistry_not_publicly_accessible import (
                containerregistry_not_publicly_accessible,
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
                        public_network_access=True,
                        admin_user_enabled=True,
                        network_rule_set=NetworkRuleSet(default_action="Allow"),
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

            check = containerregistry_not_publicly_accessible()

            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Container Registry {containerregistry_client.registries[AZURE_SUBSCRIPTION_ID][registry_id].name} from subscription {AZURE_SUBSCRIPTION_ID} allows unrestricted network access."
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

    def test_container_registry_network_access_restricted(self):
        containerregistry_client = mock.MagicMock()
        containerregistry_client.registries = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.containerregistry.containerregistry_not_publicly_accessible.containerregistry_not_publicly_accessible.containerregistry_client",
            new=containerregistry_client,
        ):
            from prowler.providers.azure.services.containerregistry.containerregistry_not_publicly_accessible.containerregistry_not_publicly_accessible import (
                containerregistry_not_publicly_accessible,
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
                        public_network_access=False,
                        admin_user_enabled=False,
                        network_rule_set=NetworkRuleSet(default_action="Deny"),
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

            check = containerregistry_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Container Registry {containerregistry_client.registries[AZURE_SUBSCRIPTION_ID][registry_id].name} from subscription {AZURE_SUBSCRIPTION_ID} does not allow unrestricted network access."
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
