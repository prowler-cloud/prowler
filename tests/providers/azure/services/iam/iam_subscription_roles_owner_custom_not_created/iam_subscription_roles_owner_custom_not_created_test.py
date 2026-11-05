from unittest import mock

from azure.mgmt.authorization.v2022_04_01.models import Permission, RoleDefinition

from prowler.providers.azure.services.iam.iam_service import IAM, Role
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)


class Test_iam_subscription_roles_owner_custom_not_created:
    def test_iam_no_roles(self):
        defender_client = mock.MagicMock
        defender_client.resource_groups = {}
        defender_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        defender_client.custom_roles = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.iam.iam_subscription_roles_owner_custom_not_created.iam_subscription_roles_owner_custom_not_created.iam_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.iam.iam_subscription_roles_owner_custom_not_created.iam_subscription_roles_owner_custom_not_created import (
                iam_subscription_roles_owner_custom_not_created,
            )

            check = iam_subscription_roles_owner_custom_not_created()
            result = check.execute()
            assert len(result) == 0

    def test_iam_custom_owner_role_created_with_all(self):
        defender_client = mock.MagicMock
        defender_client.resource_groups = {}
        defender_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        role_name = "test-role"
        defender_client.custom_roles = {
            AZURE_SUBSCRIPTION_ID: {
                "test-role-id": Role(
                    id="test-role-id",
                    name=role_name,
                    type="CustomRole",
                    assignable_scopes=["/*"],
                    permissions=[Permission(actions="*")],
                )
            }
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.iam.iam_subscription_roles_owner_custom_not_created.iam_subscription_roles_owner_custom_not_created.iam_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.iam.iam_subscription_roles_owner_custom_not_created.iam_subscription_roles_owner_custom_not_created import (
                iam_subscription_roles_owner_custom_not_created,
            )

            check = iam_subscription_roles_owner_custom_not_created()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Role {role_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} is a custom owner role."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert (
                result[0].resource_id
                == defender_client.custom_roles[AZURE_SUBSCRIPTION_ID][
                    "test-role-id"
                ].id
            )
            assert result[0].resource_name == role_name

    def test_iam_custom_owner_role_created_with_no_permissions(self):
        defender_client = mock.MagicMock
        defender_client.resource_groups = {}
        defender_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        role_name = "test-role"
        defender_client.custom_roles = {
            AZURE_SUBSCRIPTION_ID: {
                "test-role-id": Role(
                    id="test-role-id",
                    name=role_name,
                    type="type-role",
                    assignable_scopes=[""],
                    permissions=[Permission()],
                )
            }
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.iam.iam_subscription_roles_owner_custom_not_created.iam_subscription_roles_owner_custom_not_created.iam_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.iam.iam_subscription_roles_owner_custom_not_created.iam_subscription_roles_owner_custom_not_created import (
                iam_subscription_roles_owner_custom_not_created,
            )

            check = iam_subscription_roles_owner_custom_not_created()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Role {role_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} is not a custom owner role."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert (
                result[0].resource_id
                == defender_client.custom_roles[AZURE_SUBSCRIPTION_ID][
                    "test-role-id"
                ].id
            )
            assert result[0].resource_name == role_name

    def test_iam_custom_role_with_not_actions_removing_owner_permissions(self):
        defender_client = mock.MagicMock
        defender_client.resource_groups = {}
        defender_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        role_name = "test-role"
        defender_client.custom_roles = {
            AZURE_SUBSCRIPTION_ID: {
                "test-role-id": Role(
                    id="test-role-id",
                    name=role_name,
                    type="CustomRole",
                    assignable_scopes=["/*"],
                    permissions=[
                        Permission(
                            actions=["*"],
                            not_actions=[
                                "Microsoft.Authorization/*/Write",
                                "Microsoft.Authorization/*/Delete",
                                "Microsoft.Authorization/elevateAccess/Action",
                            ],
                        )
                    ],
                )
            }
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.iam.iam_subscription_roles_owner_custom_not_created.iam_subscription_roles_owner_custom_not_created.iam_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.iam.iam_subscription_roles_owner_custom_not_created.iam_subscription_roles_owner_custom_not_created import (
                iam_subscription_roles_owner_custom_not_created,
            )

            check = iam_subscription_roles_owner_custom_not_created()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Role {role_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} is not a custom owner role."
            )

    def test_iam_custom_owner_role_with_unrelated_not_actions(self):
        defender_client = mock.MagicMock
        defender_client.resource_groups = {}
        defender_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        role_name = "test-role"
        defender_client.custom_roles = {
            AZURE_SUBSCRIPTION_ID: {
                "test-role-id": Role(
                    id="test-role-id",
                    name=role_name,
                    type="CustomRole",
                    assignable_scopes=["/*"],
                    permissions=[
                        Permission(
                            actions=["*"],
                            not_actions=["Microsoft.Compute/*/Write"],
                        )
                    ],
                )
            }
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.iam.iam_subscription_roles_owner_custom_not_created.iam_subscription_roles_owner_custom_not_created.iam_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.iam.iam_subscription_roles_owner_custom_not_created.iam_subscription_roles_owner_custom_not_created import (
                iam_subscription_roles_owner_custom_not_created,
            )

            check = iam_subscription_roles_owner_custom_not_created()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Role {role_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} is a custom owner role."
            )

    def test_iam_custom_owner_role_with_partial_not_actions(self):
        defender_client = mock.MagicMock()
        defender_client.resource_groups = {}
        defender_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        role_name = "test-role"
        defender_client.custom_roles = {
            AZURE_SUBSCRIPTION_ID: {
                "test-role-id": Role(
                    id="test-role-id",
                    name=role_name,
                    type="CustomRole",
                    assignable_scopes=["/*"],
                    permissions=[
                        Permission(
                            actions=["*"],
                            not_actions=[
                                "Microsoft.Authorization/*/Write",
                                "Microsoft.Authorization/*/Delete",
                            ],
                        )
                    ],
                )
            }
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.iam.iam_subscription_roles_owner_custom_not_created.iam_subscription_roles_owner_custom_not_created.iam_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.azure.services.iam.iam_subscription_roles_owner_custom_not_created.iam_subscription_roles_owner_custom_not_created import (
                iam_subscription_roles_owner_custom_not_created,
            )

            check = iam_subscription_roles_owner_custom_not_created()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Role {role_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} is a custom owner role."
            )

    def test_get_roles_preserves_not_actions_for_custom_role(self):
        not_actions = [
            "Microsoft.Authorization/*/Write",
            "Microsoft.Authorization/*/Delete",
            "Microsoft.Authorization/elevateAccess/Action",
        ]
        role_definition = RoleDefinition(
            role_name="test-role",
            role_type="CustomRole",
            assignable_scopes=["/*"],
            permissions=[Permission(actions=["*"], not_actions=not_actions)],
        )
        # id is a readonly attribute on the SDK model, so set it after construction.
        role_definition.id = "test-role-id"

        mock_client = mock.MagicMock()
        mock_client.role_definitions.list.return_value = [role_definition]

        with (
            mock.patch(
                "prowler.providers.azure.services.iam.iam_service.IAM._get_roles",
                return_value=({}, {}),
            ),
            mock.patch(
                "prowler.providers.azure.services.iam.iam_service.IAM._get_role_assignments",
                return_value={},
            ),
        ):
            iam = IAM(set_mocked_azure_provider())

        iam.clients = {AZURE_SUBSCRIPTION_ID: mock_client}

        _, custom_roles = iam._get_roles()

        mock_client.role_definitions.list.assert_called_once_with(
            scope=f"/subscriptions/{AZURE_SUBSCRIPTION_ID}"
        )
        role = custom_roles[AZURE_SUBSCRIPTION_ID]["test-role-id"]
        assert role.name == "test-role"
        assert role.type == "CustomRole"
        assert role.permissions[0].actions == ["*"]
        assert role.permissions[0].not_actions == not_actions
