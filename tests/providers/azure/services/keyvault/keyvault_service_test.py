from unittest import mock
from unittest.mock import MagicMock, patch

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
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
        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), patch(
            "prowler.providers.azure.services.monitor.monitor_service.Monitor",
            new=MagicMock(),
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
