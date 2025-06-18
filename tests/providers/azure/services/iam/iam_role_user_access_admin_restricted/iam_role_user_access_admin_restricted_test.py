from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.iam.iam_service import Role, RoleAssignment
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_iam_role_user_access_admin_restricted:
    def test_iam_no_role_assignments(self):
        iam_client = mock.MagicMock
        iam_client.role_assignments = {}
        iam_client.roles = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.iam.iam_role_user_access_admin_restricted.iam_role_user_access_admin_restricted.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.azure.services.iam.iam_role_user_access_admin_restricted.iam_role_user_access_admin_restricted import (
                iam_role_user_access_admin_restricted,
            )

            check = iam_role_user_access_admin_restricted()
            result = check.execute()
            assert len(result) == 0

    def test_iam_user_access_administrator_role_assigned(self):
        iam_client = mock.MagicMock
        role_id = str(uuid4())
        role_assignment_id = str(uuid4())
        agent_id = str(uuid4())
        role_name = "User Access Administrator"

        iam_client.subscriptions = {
            "subscription-name-1": AZURE_SUBSCRIPTION_ID,
        }

        iam_client.role_assignments = {
            "subscription-name-1": {
                role_assignment_id: RoleAssignment(
                    id=role_assignment_id,
                    name="test-assignment",
                    scope=f"/subscriptions/{AZURE_SUBSCRIPTION_ID}",
                    agent_id=agent_id,
                    agent_type="User",
                    role_id=role_id,
                )
            }
        }
        iam_client.roles = {
            "subscription-name-1": {
                f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleDefinitions/{role_id}": Role(
                    id=role_id,
                    name=role_name,
                    type="BuiltInRole",
                    assignable_scopes=[f"/subscriptions/{AZURE_SUBSCRIPTION_ID}"],
                    permissions=[],
                )
            }
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.iam.iam_role_user_access_admin_restricted.iam_role_user_access_admin_restricted.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.azure.services.iam.iam_role_user_access_admin_restricted.iam_role_user_access_admin_restricted import (
                iam_role_user_access_admin_restricted,
            )

            check = iam_role_user_access_admin_restricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Role assignment test-assignment in subscription subscription-name-1 grants User Access Administrator role to User {agent_id}."
            )
            assert result[0].subscription == "subscription-name-1"
            assert result[0].resource_id == role_assignment_id

    def test_iam_non_user_access_administrator_role_assigned(self):
        iam_client = mock.MagicMock
        role_id = str(uuid4())
        role_assignment_id = str(uuid4())
        agent_id = str(uuid4())
        role_name = "Reader"

        iam_client.subscriptions = {
            "subscription-name-1": AZURE_SUBSCRIPTION_ID,
        }

        iam_client.role_assignments = {
            "subscription-name-1": {
                role_assignment_id: RoleAssignment(
                    id=role_assignment_id,
                    name="test-assignment",
                    scope=f"/subscriptions/{AZURE_SUBSCRIPTION_ID}",
                    agent_id=agent_id,
                    agent_type="User",
                    role_id=role_id,
                )
            }
        }
        iam_client.roles = {
            "subscription-name-1": {
                f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleDefinitions/{role_id}": Role(
                    id=role_id,
                    name=role_name,
                    type="BuiltInRole",
                    assignable_scopes=[f"/subscriptions/{AZURE_SUBSCRIPTION_ID}"],
                    permissions=[],
                )
            }
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.iam.iam_role_user_access_admin_restricted.iam_role_user_access_admin_restricted.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.azure.services.iam.iam_role_user_access_admin_restricted.iam_role_user_access_admin_restricted import (
                iam_role_user_access_admin_restricted,
            )

            check = iam_role_user_access_admin_restricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Role assignment test-assignment in subscription subscription-name-1 does not grant User Access Administrator role."
            )
            assert result[0].subscription == "subscription-name-1"
            assert result[0].resource_id == role_assignment_id
