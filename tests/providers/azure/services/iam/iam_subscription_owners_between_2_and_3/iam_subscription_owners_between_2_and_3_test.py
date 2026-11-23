from unittest import mock
from uuid import uuid4

from prowler.providers.azure.config import OWNER_ROLE_ID
from prowler.providers.azure.services.iam.iam_service import RoleAssignment
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)

CHECK = "iam_subscription_owners_between_2_and_3"
CHECK_PATH = f"prowler.providers.azure.services.iam.{CHECK}.{CHECK}"
SUBSCRIPTION_SCOPE = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}"
MANAGEMENT_GROUP_SCOPE = "/providers/Microsoft.Management/managementGroups/mg1"
READER_ROLE_ID = "acdd72a7-3385-48ef-bd42-f606fba81ae7"


def build_assignment(
    role_id: str, scope: str = SUBSCRIPTION_SCOPE, agent_id: str = None
) -> RoleAssignment:
    assignment_name = str(uuid4())
    return RoleAssignment(
        id=f"{scope}/providers/Microsoft.Authorization/roleAssignments/{assignment_name}",
        name=assignment_name,
        scope=scope,
        agent_id=agent_id or str(uuid4()),
        agent_type="User",
        role_id=role_id,
    )


def run_check(role_assignments, lookup_failed=()):
    iam_client = mock.MagicMock()
    iam_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
    iam_client.role_assignments = role_assignments
    iam_client.role_assignments_lookup_failed = set(lookup_failed)
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ),
        mock.patch(f"{CHECK_PATH}.iam_client", new=iam_client),
    ):
        from prowler.providers.azure.services.iam.iam_subscription_owners_between_2_and_3.iam_subscription_owners_between_2_and_3 import (
            iam_subscription_owners_between_2_and_3,
        )

        return iam_subscription_owners_between_2_and_3().execute()


def run_with(*assignments):
    by_id = {assignment.id: assignment for assignment in assignments}
    return run_check({AZURE_SUBSCRIPTION_ID: by_id})


class Test_iam_subscription_owners_between_2_and_3:
    def test_no_subscriptions(self):
        assert run_check({}) == []

    def test_role_assignments_lookup_failed_is_manual(self):
        result = run_check(
            {AZURE_SUBSCRIPTION_ID: {}}, lookup_failed={AZURE_SUBSCRIPTION_ID}
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Cannot evaluate the owner count of subscription {AZURE_SUBSCRIPTION_DISPLAY}: its role assignments could not be read completely. Verify that Microsoft.Authorization/roleAssignments/read (included in Reader) is granted to the scanning identity."
        )
        assert result[0].resource_id == SUBSCRIPTION_SCOPE

    def test_partial_read_with_two_owners_is_manual(self):
        owners = [build_assignment(OWNER_ROLE_ID) for _ in range(2)]
        result = run_check(
            {AZURE_SUBSCRIPTION_ID: {owner.id: owner for owner in owners}},
            lookup_failed={AZURE_SUBSCRIPTION_ID},
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"

    def test_no_role_assignments_fail(self):
        result = run_check({AZURE_SUBSCRIPTION_ID: {}})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Subscription {AZURE_SUBSCRIPTION_DISPLAY} has an owner count of 0 (0 direct, 0 inherited), outside the recommended 2 to 3."
        )

    def test_two_direct_owners_pass(self):
        result = run_with(
            build_assignment(OWNER_ROLE_ID),
            build_assignment(OWNER_ROLE_ID),
            build_assignment(READER_ROLE_ID),
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Subscription {AZURE_SUBSCRIPTION_DISPLAY} has an owner count of 2 (2 direct, 0 inherited), within the recommended 2 to 3."
        )
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID
        assert result[0].resource_id == SUBSCRIPTION_SCOPE
        assert result[0].resource_name == AZURE_SUBSCRIPTION_ID
        assert result[0].location == "global"

    def test_three_owners_pass(self):
        result = run_with(*[build_assignment(OWNER_ROLE_ID) for _ in range(3)])
        assert result[0].status == "PASS"
        assert "owner count of 3 (3 direct, 0 inherited)" in result[0].status_extended

    def test_one_owner_fail(self):
        result = run_with(
            build_assignment(OWNER_ROLE_ID), build_assignment(READER_ROLE_ID)
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Subscription {AZURE_SUBSCRIPTION_DISPLAY} has an owner count of 1 (1 direct, 0 inherited), outside the recommended 2 to 3."
        )

    def test_four_owners_fail(self):
        result = run_with(*[build_assignment(OWNER_ROLE_ID) for _ in range(4)])
        assert result[0].status == "FAIL"
        assert "owner count of 4" in result[0].status_extended

    def test_inherited_owner_counted(self):
        result = run_with(
            build_assignment(OWNER_ROLE_ID),
            build_assignment(OWNER_ROLE_ID, scope=MANAGEMENT_GROUP_SCOPE),
        )
        assert result[0].status == "PASS"
        assert "owner count of 2 (1 direct, 1 inherited)" in result[0].status_extended

    def test_owner_at_both_scopes_counted_once(self):
        agent_id = str(uuid4())
        result = run_with(
            build_assignment(OWNER_ROLE_ID, agent_id=agent_id),
            build_assignment(
                OWNER_ROLE_ID, scope=MANAGEMENT_GROUP_SCOPE, agent_id=agent_id
            ),
        )
        assert result[0].status == "FAIL"
        assert "owner count of 1 (1 direct, 0 inherited)" in result[0].status_extended

    def test_owner_at_both_scopes_with_different_casing_counted_once(self):
        agent_id = str(uuid4())
        result = run_with(
            build_assignment(OWNER_ROLE_ID, agent_id=agent_id),
            build_assignment(
                OWNER_ROLE_ID, scope=MANAGEMENT_GROUP_SCOPE, agent_id=agent_id.upper()
            ),
        )
        assert result[0].status == "FAIL"
        assert "owner count of 1 (1 direct, 0 inherited)" in result[0].status_extended

    def test_owner_role_id_matched_case_insensitively(self):
        result = run_with(
            build_assignment(OWNER_ROLE_ID.upper()),
            build_assignment(OWNER_ROLE_ID.upper()),
        )
        assert result[0].status == "PASS"
        assert "owner count of 2 (2 direct, 0 inherited)" in result[0].status_extended
