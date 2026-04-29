from unittest import mock
from unittest.mock import MagicMock, patch

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    RESOURCE_GROUP,
    set_mocked_azure_provider,
)

# TODO: we have to fix this test not to use MagicMock but set the KeyVault service while mocking the import ot the Monitor client
# from prowler.providers.azure.services.keyvault.keyvault_service import (
#     DiagnosticSetting,
#     Key,
#     KeyVault,
#     KeyVaultInfo,
#     Secret,
# )
# def mock_keyvault_get_key_vaults(_, __):
#     keyvault_info = KeyVaultInfo(
#         id="id",
#         name="name",
#         location="location",
#         resource_group="resource_group",
#         properties=None,
#         keys=[
#             Key(
#                 id="id",
#                 name="name",
#                 enabled=True,
#                 location="location",
#                 attributes=None,
#                 rotation_policy=None,
#             )
#         ],
#         secrets=[
#             Secret(
#                 id="id",
#                 name="name",
#                 enabled=True,
#                 location="location",
#                 attributes=None,
#             )
#         ],
#         monitor_diagnostic_settings=[
#             DiagnosticSetting(
#                 id="id",
#                 storage_account_id="storage_account_id",
#                 logs=[
#                     mock.MagicMock(
#                         categoty_group="audit", category="None", enabled=True
#                     ),
#                     mock.MagicMock(
#                         categoty_group="allLogs", category="None", enabled=False
#                     ),
#                 ],
#                 name="name",
#                 storage_account_name="storage_account_name",
#             )
#         ],
#     )
#     return {AZURE_SUBSCRIPTION_ID: [keyvault_info]}


# @patch(
#     "prowler.providers.azure.services.keyvault.keyvault_service.KeyVault._get_key_vaults",
#     new=mock_keyvault_get_key_vaults,
# )
class Test_keyvault_service:
    def test_keyvault_service_(self):
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
            from prowler.providers.azure.services.keyvault.keyvault_service import (  # KeyVault,
                DiagnosticSetting,
                Key,
                KeyVaultInfo,
                Secret,
            )

            # keyvault = KeyVault(set_mocked_azure_provider())
            keyvault = MagicMock()

            keyvault.key_vaults = {
                AZURE_SUBSCRIPTION_ID: [
                    KeyVaultInfo(
                        id="id",
                        name="name",
                        location="location",
                        resource_group="resource_group",
                        properties=None,
                        keys=[
                            Key(
                                id="id",
                                name="name",
                                enabled=True,
                                location="location",
                                attributes=None,
                                rotation_policy=None,
                            )
                        ],
                        secrets=[
                            Secret(
                                id="id",
                                name="name",
                                enabled=True,
                                location="location",
                                attributes=None,
                            )
                        ],
                        monitor_diagnostic_settings=[
                            DiagnosticSetting(
                                id="id",
                                storage_account_id="storage_account_id",
                                logs=[
                                    mock.MagicMock(
                                        categoty_group="audit",
                                        category="None",
                                        enabled=True,
                                    ),
                                    mock.MagicMock(
                                        categoty_group="allLogs",
                                        category="None",
                                        enabled=False,
                                    ),
                                ],
                                name="name",
                                storage_account_name="storage_account_name",
                            )
                        ],
                    )
                ]
            }

            # assert (
            #     keyvault.clients[AZURE_SUBSCRIPTION_ID].__class__.__name__
            #     == "KeyVaultManagementClient"
            # )
            assert (
                keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0].__class__.__name__
                == "KeyVaultInfo"
            )
            assert keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0].id == "id"
            assert keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0].name == "name"
            assert keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0].location == "location"
            assert (
                keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0].resource_group
                == "resource_group"
            )
            assert keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0].properties is None

            assert (
                keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0].keys[0].__class__.__name__
                == "Key"
            )
            assert keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0].keys[0].id == "id"
            assert keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0].keys[0].name == "name"
            assert keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0].keys[0].enabled is True
            assert (
                keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0].keys[0].location
                == "location"
            )
            assert (
                keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0].keys[0].attributes is None
            )
            assert (
                keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0].keys[0].rotation_policy
                is None
            )
            assert (
                keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0]
                .secrets[0]
                .__class__.__name__
                == "Secret"
            )
            assert keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0].secrets[0].id == "id"
            assert (
                keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0].secrets[0].name == "name"
            )
            assert (
                keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0].secrets[0].enabled is True
            )
            assert (
                keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0].secrets[0].location
                == "location"
            )
            assert (
                keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0].secrets[0].attributes
                is None
            )
            assert (
                keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0].secrets[0].attributes
                is None
            )
            assert (
                keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0]
                .monitor_diagnostic_settings[0]
                .id
                == "id"
            )
            assert (
                keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0]
                .monitor_diagnostic_settings[0]
                .storage_account_id
                == "storage_account_id"
            )
            assert (
                keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0]
                .monitor_diagnostic_settings[0]
                .logs[0]
                .categoty_group
                == "audit"
            )
            assert (
                keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0]
                .monitor_diagnostic_settings[0]
                .logs[0]
                .category
                == "None"
            )
            assert (
                keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0]
                .monitor_diagnostic_settings[0]
                .logs[0]
                .enabled
                is True
            )
            assert (
                keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0]
                .monitor_diagnostic_settings[0]
                .logs[1]
                .categoty_group
                == "allLogs"
            )
            assert (
                keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0]
                .monitor_diagnostic_settings[0]
                .logs[1]
                .category
                == "None"
            )
            assert (
                keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0]
                .monitor_diagnostic_settings[0]
                .logs[1]
                .enabled
                is False
            )
            assert (
                keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0]
                .monitor_diagnostic_settings[0]
                .name
                == "name"
            )
            assert (
                keyvault.key_vaults[AZURE_SUBSCRIPTION_ID][0]
                .monitor_diagnostic_settings[0]
                .storage_account_name
                == "storage_account_name"
            )


class Test_KeyVault_get_key_vaults:
    def test_get_key_vaults_no_resource_groups(self):
        mock_client = MagicMock()
        mock_client.vaults.list_by_subscription.return_value = []

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
                "prowler.providers.azure.services.keyvault.keyvault_service.KeyVault._get_key_vaults",
                return_value={},
            ),
        ):
            from prowler.providers.azure.services.keyvault.keyvault_service import (
                KeyVault,
            )

            keyvault = KeyVault(set_mocked_azure_provider())

        keyvault.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        keyvault.resource_groups = None

        provider = set_mocked_azure_provider()
        with patch(
            "prowler.providers.azure.services.keyvault.keyvault_service.monitor_client"
        ):
            result = keyvault._get_key_vaults(provider)

        mock_client.vaults.list_by_subscription.assert_called_once()
        mock_client.vaults.list_by_resource_group.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_key_vaults_with_resource_group(self):
        mock_client = MagicMock()
        mock_client.vaults.list_by_resource_group.return_value = []

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
                "prowler.providers.azure.services.keyvault.keyvault_service.KeyVault._get_key_vaults",
                return_value={},
            ),
        ):
            from prowler.providers.azure.services.keyvault.keyvault_service import (
                KeyVault,
            )

            keyvault = KeyVault(set_mocked_azure_provider())

        keyvault.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        keyvault.resource_groups = {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}

        provider = set_mocked_azure_provider()
        with patch(
            "prowler.providers.azure.services.keyvault.keyvault_service.monitor_client"
        ):
            result = keyvault._get_key_vaults(provider)

        mock_client.vaults.list_by_resource_group.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP
        )
        mock_client.vaults.list_by_subscription.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_key_vaults_empty_resource_group_for_subscription(self):
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
                "prowler.providers.azure.services.keyvault.keyvault_service.KeyVault._get_key_vaults",
                return_value={},
            ),
        ):
            from prowler.providers.azure.services.keyvault.keyvault_service import (
                KeyVault,
            )

            keyvault = KeyVault(set_mocked_azure_provider())

        keyvault.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        keyvault.resource_groups = {AZURE_SUBSCRIPTION_ID: []}

        provider = set_mocked_azure_provider()
        with patch(
            "prowler.providers.azure.services.keyvault.keyvault_service.monitor_client"
        ):
            result = keyvault._get_key_vaults(provider)

        mock_client.vaults.list_by_resource_group.assert_not_called()
        mock_client.vaults.list_by_subscription.assert_not_called()
        assert result[AZURE_SUBSCRIPTION_ID] == []
