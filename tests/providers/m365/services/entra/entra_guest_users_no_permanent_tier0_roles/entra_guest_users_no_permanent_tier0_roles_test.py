"""Tests for the entra_guest_users_no_permanent_tier0_roles check."""

from datetime import datetime, timezone
from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    Group,
    RoleAssignmentScheduleInstance,
    User,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

GLOBAL_ADMIN_ROLE = "62e90394-69f5-4237-9190-012177145e10"
PRIV_ROLE_ADMIN = "e8611ab8-c189-46e8-94e1-60213ab1f814"
NON_TIER0_ROLE = "4a5d8f65-41da-4de4-8968-e035b65339cf"

CHECK_MODULE = (
    "prowler.providers.m365.services.entra."
    "entra_guest_users_no_permanent_tier0_roles."
    "entra_guest_users_no_permanent_tier0_roles"
)


def _make_user(
    user_id=None,
    name="Test User",
    user_type="Member",
    user_principal_name="test@contoso.onmicrosoft.com",
    account_enabled=True,
):
    """Create a test User model."""
    return User(
        id=user_id or str(uuid4()),
        name=name,
        on_premises_sync_enabled=False,
        user_type=user_type,
        user_principal_name=user_principal_name,
        account_enabled=account_enabled,
    )


def _make_instance(
    principal_id,
    role_definition_id=GLOBAL_ADMIN_ROLE,
    assignment_type="Assigned",
    directory_scope_id="/",
    end_date_time=None,
):
    """Create a test RoleAssignmentScheduleInstance model."""
    return RoleAssignmentScheduleInstance(
        id=str(uuid4()),
        principal_id=principal_id,
        role_definition_id=role_definition_id,
        directory_scope_id=directory_scope_id,
        assignment_type=assignment_type,
        member_type="Direct",
        end_date_time=end_date_time,
    )


class Test_entra_guest_users_no_permanent_tier0_roles:
    """Tests for the entra_guest_users_no_permanent_tier0_roles check."""

    # ------------------------------------------------------------------
    # Required: test_no_resources
    # ------------------------------------------------------------------
    def test_no_resources(self):
        """No role assignment instances and no users: expected tenant-level PASS with 1 finding."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            entra_client.role_assignment_schedule_instances = []
            entra_client.role_assignment_schedule_instances_error = None
            entra_client.users_error = None
            entra_client.users = {}
            entra_client.groups = []

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "guestTier0Assignments"
            assert result[0].resource_name == "Guest Tier 0 role assignments"
            assert "No external user" in result[0].status_extended

    # ------------------------------------------------------------------
    # PASS scenarios
    # ------------------------------------------------------------------
    def test_no_standing_tier0_assignments_pass(self):
        """No standing Tier 0 assignments at all: expected tenant-level PASS."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            entra_client.role_assignment_schedule_instances = []
            entra_client.role_assignment_schedule_instances_error = None
            entra_client.users_error = None
            entra_client.users = {}
            entra_client.groups = []

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "guestTier0Assignments"
            assert "No external user" in result[0].status_extended

    def test_internal_member_user_with_standing_tier0_role_pass(self):
        """Internal member user with standing Tier 0 role: expected PASS (not external)."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        member_id = str(uuid4())
        member = _make_user(
            user_id=member_id,
            name="Admin User",
            user_type="Member",
            user_principal_name="admin@contoso.onmicrosoft.com",
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            entra_client.role_assignment_schedule_instances = [
                _make_instance(principal_id=member_id),
            ]
            entra_client.role_assignment_schedule_instances_error = None
            entra_client.users_error = None
            entra_client.users = {member_id: member}
            entra_client.groups = []

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "guestTier0Assignments"

    def test_activated_pim_assignment_ignored_pass(self):
        """Guest with Activated (PIM JIT) Tier 0 role: expected PASS."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        guest_id = str(uuid4())
        guest = _make_user(
            user_id=guest_id,
            name="PIM Guest",
            user_type="Guest",
            user_principal_name="pim_guest#EXT#@contoso.onmicrosoft.com",
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            entra_client.role_assignment_schedule_instances = [
                _make_instance(
                    principal_id=guest_id,
                    assignment_type="Activated",
                ),
            ]
            entra_client.role_assignment_schedule_instances_error = None
            entra_client.users_error = None
            entra_client.users = {guest_id: guest}
            entra_client.groups = []

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_non_tier0_role_pass(self):
        """Guest with standing assignment to non-Tier 0 role: expected PASS."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        guest_id = str(uuid4())
        guest = _make_user(
            user_id=guest_id,
            name="Low Priv Guest",
            user_type="Guest",
            user_principal_name="low_priv#EXT#@contoso.onmicrosoft.com",
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            entra_client.role_assignment_schedule_instances = [
                _make_instance(
                    principal_id=guest_id,
                    role_definition_id=NON_TIER0_ROLE,
                ),
            ]
            entra_client.role_assignment_schedule_instances_error = None
            entra_client.users_error = None
            entra_client.users = {guest_id: guest}
            entra_client.groups = []

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_service_principal_with_tier0_role_ignored_pass(self):
        """Service principal (not in users) with Tier 0 role: expected PASS (out of scope)."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        sp_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            # sp_id is not in users and not a role-assignable group
            entra_client.role_assignment_schedule_instances = [
                _make_instance(principal_id=sp_id),
            ]
            entra_client.role_assignment_schedule_instances_error = None
            entra_client.users_error = None
            entra_client.users = {}
            entra_client.groups = []

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_role_assignable_group_with_no_external_members_pass(self):
        """Role-assignable group with only internal members: expected PASS."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        group_id = str(uuid4())
        member_id = str(uuid4())

        internal_member = _make_user(
            user_id=member_id,
            name="Internal Admin",
            user_type="Member",
            user_principal_name="admin@contoso.onmicrosoft.com",
        )

        group = Group(
            id=group_id,
            name="Internal Admins Group",
            groupTypes=[],
            membershipRule=None,
            is_assignable_to_role=True,
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            entra_client.role_assignment_schedule_instances = [
                _make_instance(principal_id=group_id),
            ]
            entra_client.role_assignment_schedule_instances_error = None
            entra_client.users_error = None
            entra_client.users = {member_id: internal_member}
            entra_client.groups = [group]
            entra_client.tier0_role_group_members = {group.id: [member_id]}

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "guestTier0Assignments"

    def test_non_role_assignable_group_ignored_pass(self):
        """Group with is_assignable_to_role=False assigned Tier 0 role: expected PASS (ignored)."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        group_id = str(uuid4())
        guest_id = str(uuid4())

        guest = _make_user(
            user_id=guest_id,
            name="Guest In Non-Assignable Group",
            user_type="Guest",
            user_principal_name="guest_non_assignable#EXT#@contoso.onmicrosoft.com",
        )

        group = Group(
            id=group_id,
            name="Regular Group",
            groupTypes=[],
            membershipRule=None,
            is_assignable_to_role=False,
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            entra_client.role_assignment_schedule_instances = [
                _make_instance(principal_id=group_id),
            ]
            entra_client.role_assignment_schedule_instances_error = None
            entra_client.users_error = None
            entra_client.users = {guest_id: guest}
            entra_client.groups = [group]

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            # Group is not role-assignable, so it's not expanded; not a user either -> PASS
            assert len(result) == 1
            assert result[0].status == "PASS"

    # ------------------------------------------------------------------
    # FAIL scenarios
    # ------------------------------------------------------------------
    def test_guest_user_with_standing_tier0_role_fail(self):
        """Guest user with standing Tier 0 role: expected FAIL."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        guest_id = str(uuid4())
        guest = _make_user(
            user_id=guest_id,
            name="John Partner",
            user_type="Guest",
            user_principal_name="john_partner.com#EXT#@contoso.onmicrosoft.com",
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            entra_client.role_assignment_schedule_instances = [
                _make_instance(principal_id=guest_id),
            ]
            entra_client.role_assignment_schedule_instances_error = None
            entra_client.users_error = None
            entra_client.users = {guest_id: guest}
            entra_client.groups = []

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == guest_id
            assert result[0].resource_name == "John Partner"
            assert "John Partner" in result[0].status_extended
            assert "Global Administrator" in result[0].status_extended
            assert "permanent" in result[0].status_extended
            assert "tenant-wide" in result[0].status_extended

    def test_ext_member_user_with_standing_tier0_role_fail(self):
        """Member user with #EXT# in UPN: expected FAIL (B2B converted user)."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        ext_id = str(uuid4())
        ext_user = _make_user(
            user_id=ext_id,
            name="Jane External",
            user_type="Member",
            user_principal_name="jane_ext.com#EXT#@contoso.onmicrosoft.com",
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            entra_client.role_assignment_schedule_instances = [
                _make_instance(principal_id=ext_id),
            ]
            entra_client.role_assignment_schedule_instances_error = None
            entra_client.users_error = None
            entra_client.users = {ext_id: ext_user}
            entra_client.groups = []

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Jane External" in result[0].status_extended

    def test_time_bound_standing_assignment_fail(self):
        """Guest with time-bound standing Tier 0 role (endDateTime set): expected FAIL."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        guest_id = str(uuid4())
        guest = _make_user(
            user_id=guest_id,
            name="Temp Guest",
            user_type="Guest",
            user_principal_name="temp_guest#EXT#@contoso.onmicrosoft.com",
        )
        end_dt = datetime(2027, 6, 15, tzinfo=timezone.utc)

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            entra_client.role_assignment_schedule_instances = [
                _make_instance(
                    principal_id=guest_id,
                    end_date_time=end_dt,
                ),
            ]
            entra_client.role_assignment_schedule_instances_error = None
            entra_client.users_error = None
            entra_client.users = {guest_id: guest}
            entra_client.groups = []

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "time-bound" in result[0].status_extended
            assert "2027" in result[0].status_extended

    def test_disabled_guest_with_standing_tier0_role_fail(self):
        """Disabled guest with standing Tier 0 role: expected FAIL (still a risk)."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        guest_id = str(uuid4())
        guest = _make_user(
            user_id=guest_id,
            name="Disabled Guest",
            user_type="Guest",
            user_principal_name="disabled#EXT#@contoso.onmicrosoft.com",
            account_enabled=False,
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            entra_client.role_assignment_schedule_instances = [
                _make_instance(principal_id=guest_id),
            ]
            entra_client.role_assignment_schedule_instances_error = None
            entra_client.users_error = None
            entra_client.users = {guest_id: guest}
            entra_client.groups = []

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_guest_in_role_assignable_group_fail(self):
        """Guest user inherits Tier 0 role via role-assignable group: expected FAIL."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        guest_id = str(uuid4())
        group_id = str(uuid4())
        member_id = str(uuid4())

        guest = _make_user(
            user_id=guest_id,
            name="Group Guest",
            user_type="Guest",
            user_principal_name="group_guest#EXT#@contoso.onmicrosoft.com",
        )
        internal_member = _make_user(
            user_id=member_id,
            name="Internal Admin",
            user_type="Member",
            user_principal_name="admin@contoso.onmicrosoft.com",
        )

        group = Group(
            id=group_id,
            name="Tier0 Admins",
            groupTypes=[],
            membershipRule=None,
            is_assignable_to_role=True,
        )

        # Create an async mock that returns both member IDs
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            entra_client.role_assignment_schedule_instances = [
                _make_instance(principal_id=group_id),
            ]
            entra_client.role_assignment_schedule_instances_error = None
            entra_client.users_error = None
            entra_client.users = {
                guest_id: guest,
                member_id: internal_member,
            }
            entra_client.groups = [group]
            entra_client.tier0_role_group_members = {group.id: [guest_id, member_id]}

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            # Should have 1 FAIL for the guest member, internal member is ignored
            fail_results = [r for r in result if r.status == "FAIL"]
            assert len(fail_results) == 1
            assert "via group 'Tier0 Admins'" in fail_results[0].status_extended
            assert "Group Guest" in fail_results[0].status_extended

    def test_multiple_guest_assignments_multiple_fails(self):
        """Multiple guests with standing Tier 0 roles: expected one FAIL per assignment."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        guest1_id = str(uuid4())
        guest2_id = str(uuid4())
        guest1 = _make_user(
            user_id=guest1_id,
            name="Guest One",
            user_type="Guest",
            user_principal_name="guest1#EXT#@contoso.onmicrosoft.com",
        )
        guest2 = _make_user(
            user_id=guest2_id,
            name="Guest Two",
            user_type="Guest",
            user_principal_name="guest2#EXT#@contoso.onmicrosoft.com",
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            entra_client.role_assignment_schedule_instances = [
                _make_instance(principal_id=guest1_id),
                _make_instance(
                    principal_id=guest2_id,
                    role_definition_id=PRIV_ROLE_ADMIN,
                ),
            ]
            entra_client.role_assignment_schedule_instances_error = None
            entra_client.users_error = None
            entra_client.users = {
                guest1_id: guest1,
                guest2_id: guest2,
            }
            entra_client.groups = []

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 2
            assert all(r.status == "FAIL" for r in result)
            names = {r.resource_name for r in result}
            assert "Guest One" in names
            assert "Guest Two" in names

    def test_directory_scope_non_root(self):
        """Guest with Tier 0 role on AU scope: FAIL with scope in status_extended."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        guest_id = str(uuid4())
        guest = _make_user(
            user_id=guest_id,
            name="Scoped Guest",
            user_type="Guest",
            user_principal_name="scoped#EXT#@contoso.onmicrosoft.com",
        )
        au_scope = "/administrativeUnits/abc123"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            entra_client.role_assignment_schedule_instances = [
                _make_instance(
                    principal_id=guest_id,
                    directory_scope_id=au_scope,
                ),
            ]
            entra_client.role_assignment_schedule_instances_error = None
            entra_client.users_error = None
            entra_client.users = {guest_id: guest}
            entra_client.groups = []

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert au_scope in result[0].status_extended

    # ------------------------------------------------------------------
    # MANUAL scenarios
    # ------------------------------------------------------------------
    def test_role_assignment_instances_unavailable_manual(self):
        """Role assignment data unavailable: expected MANUAL."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            entra_client.role_assignment_schedule_instances = None
            entra_client.role_assignment_schedule_instances_error = (
                "Cannot evaluate guest Tier 0 role assignments: role "
                "assignment schedule instances could not be retrieved. "
                "Grant RoleAssignmentSchedule.Read.Directory (or "
                "RoleManagement.Read.Directory) to the Prowler application."
            )
            entra_client.users_error = None
            entra_client.users = {}
            entra_client.groups = []

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert result[0].resource_id == "guestTier0Assignments"
            assert "RoleAssignmentSchedule.Read.Directory" in result[0].status_extended

    def test_role_assignment_instances_none_no_error_message_manual(self):
        """Role assignment data is None with no specific error: expected MANUAL with default message."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            entra_client.role_assignment_schedule_instances = None
            entra_client.role_assignment_schedule_instances_error = None
            entra_client.users_error = None
            entra_client.users = {}
            entra_client.groups = []

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "could not be retrieved" in result[0].status_extended

    def test_users_unavailable_manual(self):
        """Users directory unavailable: expected MANUAL."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            entra_client.role_assignment_schedule_instances = []
            entra_client.role_assignment_schedule_instances_error = None
            entra_client.users_error = (
                "Insufficient privileges to read users and directory roles."
            )
            entra_client.users = {}
            entra_client.groups = []

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "user directory could not be read" in result[0].status_extended

    def test_group_members_unreadable_manual(self):
        """Group members cannot be fetched: expected MANUAL for that group."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        group_id = str(uuid4())

        group = Group(
            id=group_id,
            name="Secret Admins",
            groupTypes=[],
            membershipRule=None,
            is_assignable_to_role=True,
        )

        # Return None to simulate failure to read group members
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            entra_client.role_assignment_schedule_instances = [
                _make_instance(principal_id=group_id),
            ]
            entra_client.role_assignment_schedule_instances_error = None
            entra_client.users_error = None
            entra_client.users = {}
            entra_client.groups = [group]
            entra_client.tier0_role_group_members = {group.id: None}

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            # MANUAL for unreadable group + PASS (no external users found otherwise)
            manual_results = [r for r in result if r.status == "MANUAL"]
            pass_results = [r for r in result if r.status == "PASS"]
            assert len(manual_results) == 1
            assert manual_results[0].resource_id == group_id
            assert "Secret Admins" in manual_results[0].status_extended
            assert "could not be read" in manual_results[0].status_extended
            assert len(pass_results) == 1

    # ------------------------------------------------------------------
    # Mixed / complex scenarios
    # ------------------------------------------------------------------
    def test_mixed_direct_fail_and_group_manual(self):
        """Direct guest FAIL + unreadable group MANUAL in same execution."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        guest_id = str(uuid4())
        group_id = str(uuid4())

        guest = _make_user(
            user_id=guest_id,
            name="Direct Guest",
            user_type="Guest",
            user_principal_name="direct_guest#EXT#@contoso.onmicrosoft.com",
        )

        group = Group(
            id=group_id,
            name="Unreadable Group",
            groupTypes=[],
            membershipRule=None,
            is_assignable_to_role=True,
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            entra_client.role_assignment_schedule_instances = [
                _make_instance(principal_id=guest_id),
                _make_instance(principal_id=group_id),
            ]
            entra_client.role_assignment_schedule_instances_error = None
            entra_client.users_error = None
            entra_client.users = {guest_id: guest}
            entra_client.groups = [group]
            entra_client.tier0_role_group_members = {group.id: None}

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            fail_results = [r for r in result if r.status == "FAIL"]
            manual_results = [r for r in result if r.status == "MANUAL"]
            pass_results = [r for r in result if r.status == "PASS"]
            # 1 FAIL for direct guest, 1 MANUAL for unreadable group, no PASS (fail_found=True)
            assert len(fail_results) == 1
            assert len(manual_results) == 1
            assert len(pass_results) == 0
            assert fail_results[0].resource_id == guest_id
            assert manual_results[0].resource_id == group_id

    def test_mixed_guest_and_internal_user_assignments(self):
        """Guest + internal user both with standing Tier 0: FAIL only for guest, no PASS."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        guest_id = str(uuid4())
        member_id = str(uuid4())

        guest = _make_user(
            user_id=guest_id,
            name="External Admin",
            user_type="Guest",
            user_principal_name="ext_admin#EXT#@contoso.onmicrosoft.com",
        )
        member = _make_user(
            user_id=member_id,
            name="Internal Admin",
            user_type="Member",
            user_principal_name="admin@contoso.onmicrosoft.com",
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            entra_client.role_assignment_schedule_instances = [
                _make_instance(principal_id=guest_id),
                _make_instance(principal_id=member_id),
            ]
            entra_client.role_assignment_schedule_instances_error = None
            entra_client.users_error = None
            entra_client.users = {
                guest_id: guest,
                member_id: member,
            }
            entra_client.groups = []

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            # 1 FAIL for the guest, no PASS since fail_found is True
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == guest_id
            assert "External Admin" in result[0].status_extended

    def test_guest_user_type_case_insensitive(self):
        """user_type 'GUEST' (uppercase) is still detected as external: expected FAIL."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        guest_id = str(uuid4())
        guest = _make_user(
            user_id=guest_id,
            name="Case Guest",
            user_type="GUEST",
            user_principal_name="case_guest@partner.com",
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            entra_client.role_assignment_schedule_instances = [
                _make_instance(principal_id=guest_id),
            ]
            entra_client.role_assignment_schedule_instances_error = None
            entra_client.users_error = None
            entra_client.users = {guest_id: guest}
            entra_client.groups = []

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_guest_same_user_two_tier0_roles_two_fails(self):
        """Same guest with two different standing Tier 0 roles: expected two FAILs."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        guest_id = str(uuid4())
        guest = _make_user(
            user_id=guest_id,
            name="Double Role Guest",
            user_type="Guest",
            user_principal_name="double#EXT#@contoso.onmicrosoft.com",
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_guest_users_no_permanent_tier0_roles.entra_guest_users_no_permanent_tier0_roles import (
                entra_guest_users_no_permanent_tier0_roles,
            )

            entra_client.role_assignment_schedule_instances = [
                _make_instance(
                    principal_id=guest_id,
                    role_definition_id=GLOBAL_ADMIN_ROLE,
                ),
                _make_instance(
                    principal_id=guest_id,
                    role_definition_id=PRIV_ROLE_ADMIN,
                ),
            ]
            entra_client.role_assignment_schedule_instances_error = None
            entra_client.users_error = None
            entra_client.users = {guest_id: guest}
            entra_client.groups = []

            check = entra_guest_users_no_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 2
            assert all(r.status == "FAIL" for r in result)
            assert all(r.resource_id == guest_id for r in result)
            role_names_in_extended = {r.status_extended for r in result}
            # Verify both roles appear across the findings
            combined = " ".join(role_names_in_extended)
            assert "Global Administrator" in combined
            assert "Privileged Role Administrator" in combined
