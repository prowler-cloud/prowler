from unittest import mock
from unittest.mock import MagicMock, patch

from azure.mgmt.keyvault.v2023_07_01.models import Key as ArmKey
from azure.mgmt.keyvault.v2023_07_01.models import KeyAttributes as ArmKeyAttributes

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    RESOURCE_GROUP,
    RESOURCE_GROUP_LIST,
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
        mock_client.vaults = MagicMock()
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

        with patch(
            "prowler.providers.azure.services.keyvault.keyvault_service.monitor_client"
        ):
            result = keyvault._get_key_vaults()

        mock_client.vaults.list_by_subscription.assert_called_once()
        mock_client.vaults.list_by_resource_group.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_key_vaults_with_resource_group(self):
        mock_client = MagicMock()
        mock_client.vaults = MagicMock()
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

        with patch(
            "prowler.providers.azure.services.keyvault.keyvault_service.monitor_client"
        ):
            result = keyvault._get_key_vaults()

        mock_client.vaults.list_by_resource_group.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP
        )
        mock_client.vaults.list_by_subscription.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_key_vaults_empty_resource_group_for_subscription(self):
        mock_client = MagicMock()
        mock_client.vaults = MagicMock()

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

        with patch(
            "prowler.providers.azure.services.keyvault.keyvault_service.monitor_client"
        ):
            result = keyvault._get_key_vaults()

        mock_client.vaults.list_by_resource_group.assert_not_called()
        mock_client.vaults.list_by_subscription.assert_not_called()
        assert result[AZURE_SUBSCRIPTION_ID] == []

    def test_get_key_vaults_with_multiple_resource_groups(self):
        mock_client = MagicMock()
        mock_client.vaults = MagicMock()
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
        keyvault.resource_groups = {AZURE_SUBSCRIPTION_ID: RESOURCE_GROUP_LIST}

        with patch(
            "prowler.providers.azure.services.keyvault.keyvault_service.monitor_client"
        ):
            result = keyvault._get_key_vaults()

        assert mock_client.vaults.list_by_resource_group.call_count == len(
            RESOURCE_GROUP_LIST
        )
        mock_client.vaults.list_by_subscription.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_key_vaults_with_mixed_case_resource_group(self):
        mock_client = MagicMock()
        mock_client.vaults = MagicMock()
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
        keyvault.resource_groups = {AZURE_SUBSCRIPTION_ID: ["MyRG"]}

        with patch(
            "prowler.providers.azure.services.keyvault.keyvault_service.monitor_client"
        ):
            keyvault._get_key_vaults()

        mock_client.vaults.list_by_resource_group.assert_called_once_with(
            resource_group_name="MyRG"
        )


class Test_KeyVault_get_keys:
    def test_get_keys_fetches_arm_key_details_for_rotation_policy(self):
        listed_key = ArmKey(attributes=ArmKeyAttributes(enabled=True))
        listed_key.id = "/subscriptions/subscription/resourceGroups/resource-group/providers/Microsoft.KeyVault/vaults/vault/keys/key"
        listed_key.name = "key"
        listed_key.location = "westeurope"

        detailed_key = ArmKey.deserialize(
            {
                "properties": {
                    "attributes": {"enabled": True},
                    "rotationPolicy": {
                        "lifetimeActions": [
                            {"action": {"type": "rotate"}},
                            {"action": {"type": "notify"}},
                        ]
                    },
                }
            }
        )

        mock_client = MagicMock()
        mock_client.keys.list.return_value = [listed_key]
        mock_client.keys.get.return_value = detailed_key

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
                "prowler.providers.azure.services.keyvault.keyvault_service.KeyVault._get_key_vaults",
                return_value={},
            ),
        ):
            from prowler.providers.azure.services.keyvault.keyvault_service import (
                KeyVault,
            )

            keyvault = KeyVault(set_mocked_azure_provider())

        keyvault.clients = {AZURE_SUBSCRIPTION_ID: mock_client}

        with patch(
            "prowler.providers.azure.services.keyvault.keyvault_service.KeyClient",
            create=True,
        ) as data_plane_key_client:
            data_plane_key_client.return_value.list_properties_of_keys.return_value = []
            keys = keyvault._get_keys(
                AZURE_SUBSCRIPTION_ID,
                RESOURCE_GROUP,
                "vault",
            )

        assert len(keys) == 1
        assert keys[0].rotation_policy is not None
        assert [
            action.action for action in keys[0].rotation_policy.lifetime_actions
        ] == ["Rotate", "Notify"]
        mock_client.keys.get.assert_called_once_with(
            RESOURCE_GROUP,
            "vault",
            "key",
        )
        data_plane_key_client.assert_not_called()

    def test_get_keys_preserves_missing_arm_rotation_policy(self):
        listed_key = ArmKey(attributes=ArmKeyAttributes(enabled=True))
        listed_key.id = "/subscriptions/subscription/resourceGroups/resource-group/providers/Microsoft.KeyVault/vaults/vault/keys/key"
        listed_key.name = "key"
        listed_key.location = "westeurope"
        detailed_key = ArmKey(attributes=ArmKeyAttributes(enabled=True))

        mock_client = MagicMock()
        mock_client.keys.list.return_value = [listed_key]
        mock_client.keys.get.return_value = detailed_key

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
                "prowler.providers.azure.services.keyvault.keyvault_service.KeyVault._get_key_vaults",
                return_value={},
            ),
        ):
            from prowler.providers.azure.services.keyvault.keyvault_service import (
                KeyVault,
            )

            keyvault = KeyVault(set_mocked_azure_provider())

        keyvault.clients = {AZURE_SUBSCRIPTION_ID: mock_client}

        with patch(
            "prowler.providers.azure.services.keyvault.keyvault_service.KeyClient",
            create=True,
        ) as data_plane_key_client:
            keys = keyvault._get_keys(
                AZURE_SUBSCRIPTION_ID,
                RESOURCE_GROUP,
                "vault",
            )

        assert len(keys) == 1
        assert keys[0].rotation_policy is None
        mock_client.keys.get.assert_called_once_with(
            RESOURCE_GROUP,
            "vault",
            "key",
        )
        data_plane_key_client.assert_not_called()

    def test_get_keys_preserves_expiration_checks_when_arm_details_fail(self):
        listed_key = ArmKey(attributes=ArmKeyAttributes(enabled=True))
        listed_key.id = "/subscriptions/subscription/resourceGroups/resource-group/providers/Microsoft.KeyVault/vaults/vault/keys/key"
        listed_key.name = "key"
        listed_key.location = "westeurope"

        mock_client = MagicMock()
        healthy_key = ArmKey(attributes=ArmKeyAttributes(enabled=True))
        healthy_key.id = listed_key.id + "-healthy"
        healthy_key.name = "healthy-key"
        healthy_key.location = listed_key.location
        another_unreadable_key = ArmKey(attributes=ArmKeyAttributes(enabled=True))
        another_unreadable_key.id = listed_key.id + "-unreadable"
        another_unreadable_key.name = "another-unreadable-key"
        another_unreadable_key.location = listed_key.location
        mock_client.keys.list.return_value = [
            listed_key,
            healthy_key,
            another_unreadable_key,
        ]
        mock_client.keys.get.side_effect = [
            Exception("details unavailable"),
            ArmKey(attributes=ArmKeyAttributes(enabled=True)),
            Exception("details unavailable"),
        ]

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
                "prowler.providers.azure.services.keyvault.keyvault_service.KeyVault._get_key_vaults",
                return_value={},
            ),
        ):
            from prowler.providers.azure.services.keyvault.keyvault_service import (
                KeyVault,
                KeyVaultInfo,
                VaultProperties,
            )

            keyvault = KeyVault(set_mocked_azure_provider())

        keyvault.clients = {AZURE_SUBSCRIPTION_ID: mock_client}

        keys = keyvault._get_keys(
            AZURE_SUBSCRIPTION_ID,
            RESOURCE_GROUP,
            "vault",
        )

        assert len(keys) == 3
        assert keys[0].id == listed_key.id
        assert keys[0].enabled is True
        assert keys[0].attributes.expires is None
        assert keys[0].rotation_policy is None
        assert keys[0].rotation_policy_accessible is False
        assert keys[1].rotation_policy_accessible is True
        assert keys[2].rotation_policy_accessible is False
        mock_client.keys.get.assert_has_calls(
            [
                mock.call(RESOURCE_GROUP, "vault", "key"),
                mock.call(RESOURCE_GROUP, "vault", "healthy-key"),
                mock.call(RESOURCE_GROUP, "vault", "another-unreadable-key"),
            ]
        )

        keyvault.subscriptions = {AZURE_SUBSCRIPTION_ID: "subscription"}
        keyvault.key_vaults = {
            AZURE_SUBSCRIPTION_ID: [
                KeyVaultInfo(
                    id="vault-id",
                    name="vault",
                    location="westeurope",
                    resource_group=RESOURCE_GROUP,
                    properties=VaultProperties(
                        tenant_id="tenant",
                        enable_rbac_authorization=False,
                        private_endpoint_connections=[],
                        enable_soft_delete=True,
                        enable_purge_protection=True,
                    ),
                    keys=keys,
                )
            ]
        }
        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            patch(
                "prowler.providers.azure.services.keyvault.keyvault_key_expiration_set_in_non_rbac.keyvault_key_expiration_set_in_non_rbac.keyvault_client",
                new=keyvault,
            ),
            patch(
                "prowler.providers.azure.services.keyvault.keyvault_key_rotation_enabled.keyvault_key_rotation_enabled.keyvault_client",
                new=keyvault,
            ),
        ):
            from prowler.providers.azure.services.keyvault.keyvault_key_expiration_set_in_non_rbac.keyvault_key_expiration_set_in_non_rbac import (
                keyvault_key_expiration_set_in_non_rbac,
            )
            from prowler.providers.azure.services.keyvault.keyvault_key_rotation_enabled.keyvault_key_rotation_enabled import (
                keyvault_key_rotation_enabled,
            )

            expiration_findings = keyvault_key_expiration_set_in_non_rbac().execute()
            assert [
                (finding.resource_id, finding.status) for finding in expiration_findings
            ] == [
                (listed_key.id, "FAIL"),
                (healthy_key.id, "FAIL"),
                (another_unreadable_key.id, "FAIL"),
            ]
            rotation_findings = keyvault_key_rotation_enabled().execute()
            assert [
                (finding.resource_id, finding.status) for finding in rotation_findings
            ] == [
                (healthy_key.id, "FAIL"),
                (f"/subscriptions/{AZURE_SUBSCRIPTION_ID}", "MANUAL"),
            ]
            assert rotation_findings[1].subscription == AZURE_SUBSCRIPTION_ID
            assert (
                "Microsoft.KeyVault/vaults/keys/read"
                in rotation_findings[1].status_extended
            )
