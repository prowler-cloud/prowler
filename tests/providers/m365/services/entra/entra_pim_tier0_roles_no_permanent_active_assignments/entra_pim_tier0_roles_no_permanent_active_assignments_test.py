"""Tests for entra_pim_tier0_roles_no_permanent_active_assignments check."""

from datetime import datetime, timezone
from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    GLOBAL_ADMINISTRATOR_ROLE_TEMPLATE_ID,
    ApplicationsConditions,
    ConditionalAccessPolicy,
    ConditionalAccessPolicyState,
    Conditions,
    GrantControlOperator,
    GrantControls,
    PersistentBrowser,
    RoleAssignmentScheduleInstance,
    SessionControls,
    SignInFrequency,
    SignInFrequencyInterval,
    SubscribedSku,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = (
    "prowler.providers.m365.services.entra."
    "entra_pim_tier0_roles_no_permanent_active_assignments."
    "entra_pim_tier0_roles_no_permanent_active_assignments"
)

# Well-known role template IDs used in tests.
GA_ROLE_ID = GLOBAL_ADMINISTRATOR_ROLE_TEMPLATE_ID
PRA_ROLE_ID = "e8611ab8-c189-46e8-94e1-60213ab1f814"  # Privileged Role Admin
DIR_SYNC_ROLE_ID = "d29b2b05-8046-44ba-8758-1e26182fcf32"  # Dir Sync Accounts


def _make_instance(
    id="inst-1",
    principal_id="user-1",
    role_definition_id=GA_ROLE_ID,
    assignment_type="Assigned",
    member_type="Direct",
    principal_odata_type="#microsoft.graph.user",
    principal_display_name="Alice Admin",
    principal_upn="alice@contoso.com",
    directory_scope_id="/",
    end_date_time=None,
):
    """Helper to build a RoleAssignmentScheduleInstance for tests."""
    return RoleAssignmentScheduleInstance(
        id=id,
        principal_id=principal_id,
        role_definition_id=role_definition_id,
        directory_scope_id=directory_scope_id,
        assignment_type=assignment_type,
        member_type=member_type,
        end_date_time=end_date_time,
        principal_odata_type=principal_odata_type,
        principal_display_name=principal_display_name,
        principal_upn=principal_upn,
    )


def _make_ca_policy(policy_id="policy-1", excluded_users=None, state="enabled"):
    """Helper to build a minimal Conditional Access policy for break-glass tests."""
    return ConditionalAccessPolicy(
        id=policy_id,
        display_name=f"Policy {policy_id}",
        conditions=Conditions(
            application_conditions=ApplicationsConditions(
                included_applications=["All"],
                excluded_applications=[],
                included_user_actions=[],
            ),
            user_conditions=UsersConditions(
                included_users=["All"],
                excluded_users=excluded_users or [],
                included_groups=[],
                excluded_groups=[],
                included_roles=[],
                excluded_roles=[],
            ),
        ),
        session_controls=SessionControls(
            persistent_browser=PersistentBrowser(is_enabled=False, mode="always"),
            sign_in_frequency=SignInFrequency(
                is_enabled=False,
                frequency=None,
                type=None,
                interval=SignInFrequencyInterval.EVERY_TIME,
            ),
        ),
        grant_controls=GrantControls(
            built_in_controls=[],
            operator=GrantControlOperator.OR,
        ),
        state=ConditionalAccessPolicyState(state),
    )


def _p2_sku():
    """Return a SubscribedSku with AAD_PREMIUM_P2."""
    return SubscribedSku(
        sku_id="sku-p2",
        sku_part_number="AAD_PREMIUM_P2",
        capability_status="Enabled",
        service_plan_names=["AAD_PREMIUM_P2"],
    )


def _no_p2_sku():
    """Return a SubscribedSku without PIM-related plans."""
    return SubscribedSku(
        sku_id="sku-e3",
        sku_part_number="ENTERPRISEPACK",
        capability_status="Enabled",
        service_plan_names=["EXCHANGE_S_ENTERPRISE"],
    )


_SENTINEL = object()


class Test_entra_pim_tier0_roles_no_permanent_active_assignments:
    """Tests for the PIM Tier 0 standing-assignment check."""

    def _run(
        self,
        instances=None,
        skus=None,
        skus_error=None,
        instances_error=None,
        conditional_access_policies=_SENTINEL,
        audit_config=None,
    ):
        """Set up mocks and execute the check."""
        entra_client = mock.MagicMock()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_pim_tier0_roles_no_permanent_active_assignments.entra_pim_tier0_roles_no_permanent_active_assignments import (
                entra_pim_tier0_roles_no_permanent_active_assignments,
            )

            entra_client.role_assignment_schedule_instances = instances
            entra_client.subscribed_skus = skus
            entra_client.subscribed_skus_error = skus_error
            entra_client.role_assignment_schedule_instances_error = instances_error
            entra_client.conditional_access_policies = (
                conditional_access_policies
                if conditional_access_policies is not _SENTINEL
                else {}
            )
            entra_client.audit_config = audit_config or {}
            entra_client.tenant_domain = DOMAIN

            return entra_pim_tier0_roles_no_permanent_active_assignments().execute()

    # --- Licence gates ---

    def test_no_pim_licence_returns_manual(self):
        """MANUAL when tenant has no P2/Governance licence."""
        result = self._run(skus=[_no_p2_sku()])
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "no Microsoft Entra ID P2" in result[0].status_extended
        assert result[0].resource_id == "tier0RoleAssignments"

    def test_skus_error_returns_manual(self):
        """MANUAL when subscribed SKUs cannot be read."""
        result = self._run(
            skus=None,
            skus_error="Unable to retrieve subscribed SKUs: ODataError: 403",
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "licence status unknown" in result[0].status_extended

    # --- Data availability gates ---

    def test_instances_none_returns_manual(self):
        """MANUAL when roleAssignmentScheduleInstances cannot be read."""
        result = self._run(
            skus=[_p2_sku()],
            instances=None,
            instances_error="API error",
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            "roleAssignmentScheduleInstances could not be read"
            in result[0].status_extended
        )
        assert "RoleAssignmentSchedule.Read.Directory" in result[0].status_extended

    # --- No Tier 0 instances ---

    def test_no_tier0_instances_pass(self):
        """PASS when no Tier 0 instances exist for users/groups."""
        result = self._run(skus=[_p2_sku()], instances=[])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == "tier0RoleAssignments"
        assert "No active Tier 0 role assignment instances" in result[0].status_extended

    # --- Activated (PIM JIT) ---

    def test_activated_assignment_passes(self):
        """PASS when the assignment is a PIM just-in-time activation."""
        inst = _make_instance(
            assignment_type="Activated",
            end_date_time=datetime(2026, 10, 8, 11, 0, 0, tzinfo=timezone.utc),
        )
        result = self._run(skus=[_p2_sku()], instances=[inst])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "just-in-time activation" in result[0].status_extended
        assert result[0].resource_id == "inst-1"

    def test_activated_group_assignment_passes(self):
        """PASS for a group with an Activated (PIM JIT) assignment."""
        inst = _make_instance(
            assignment_type="Activated",
            principal_odata_type="#microsoft.graph.group",
            principal_display_name="PIM Admins Group",
            principal_upn=None,
            end_date_time=datetime(2026, 10, 8, 11, 0, 0, tzinfo=timezone.utc),
        )
        result = self._run(skus=[_p2_sku()], instances=[inst])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "just-in-time activation" in result[0].status_extended
        assert "Group" in result[0].status_extended

    # --- Standing Assigned -> FAIL ---

    def test_standing_permanent_assignment_fails(self):
        """FAIL for a standing permanent Assigned user on a Tier 0 role."""
        inst = _make_instance(
            role_definition_id=PRA_ROLE_ID,
            principal_display_name="Eve Bad",
            principal_upn="eve@contoso.com",
        )
        result = self._run(skus=[_p2_sku()], instances=[inst])
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "standing permanent assignment" in result[0].status_extended
        assert "Privileged Role Administrator" in result[0].status_extended
        assert "eve@contoso.com" in result[0].status_extended
        assert "PIM eligible assignment" in result[0].status_extended

    def test_standing_timebound_assignment_fails(self):
        """FAIL for a standing time-bound Assigned user on a Tier 0 role."""
        end_dt = datetime(2027, 1, 1, tzinfo=timezone.utc)
        inst = _make_instance(end_date_time=end_dt)
        result = self._run(skus=[_p2_sku()], instances=[inst])
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "time-bound" in result[0].status_extended
        assert "2027-01-01" in result[0].status_extended

    # --- Break-glass exceptions ---

    def test_break_glass_ga_within_cap_passes(self):
        """PASS for a break-glass user with standing GA within the cap."""
        bg_user_id = "break-glass-1"
        inst = _make_instance(
            principal_id=bg_user_id,
            principal_display_name="Break Glass 1",
            principal_upn="bg1@contoso.com",
        )
        # Create a CA policy that excludes the break-glass user.
        ca_policies = {
            "p1": _make_ca_policy(excluded_users=[bg_user_id]),
        }
        result = self._run(
            skus=[_p2_sku()],
            instances=[inst],
            conditional_access_policies=ca_policies,
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "emergency-access" in result[0].status_extended
        assert "1 of 2 allowed" in result[0].status_extended

    def test_two_break_glass_ga_at_cap_passes(self):
        """PASS for two break-glass users with standing GA at exactly the cap (2/2)."""
        bg1 = "break-glass-1"
        bg2 = "break-glass-2"
        instances = [
            _make_instance(
                id="i1",
                principal_id=bg1,
                principal_display_name="BG1",
                principal_upn="bg1@contoso.com",
            ),
            _make_instance(
                id="i2",
                principal_id=bg2,
                principal_display_name="BG2",
                principal_upn="bg2@contoso.com",
            ),
        ]
        ca_policies = {
            "p1": _make_ca_policy(excluded_users=[bg1, bg2]),
        }
        result = self._run(
            skus=[_p2_sku()],
            instances=instances,
            conditional_access_policies=ca_policies,
            audit_config={"max_permanent_break_glass_global_admins": 2},
        )
        assert len(result) == 2
        assert all(r.status == "PASS" for r in result)
        assert all("emergency-access" in r.status_extended for r in result)
        assert all("2 of 2 allowed" in r.status_extended for r in result)

    def test_break_glass_exceeding_cap_fails(self):
        """FAIL when break-glass GA count exceeds the configured maximum."""
        bg1 = "break-glass-1"
        bg2 = "break-glass-2"
        bg3 = "break-glass-3"
        instances = [
            _make_instance(id="i1", principal_id=bg1, principal_display_name="BG1"),
            _make_instance(id="i2", principal_id=bg2, principal_display_name="BG2"),
            _make_instance(id="i3", principal_id=bg3, principal_display_name="BG3"),
        ]
        ca_policies = {
            "p1": _make_ca_policy(excluded_users=[bg1, bg2, bg3]),
        }
        result = self._run(
            skus=[_p2_sku()],
            instances=instances,
            conditional_access_policies=ca_policies,
            audit_config={"max_permanent_break_glass_global_admins": 2},
        )
        # All 3 should FAIL because the count (3) exceeds the cap (2).
        assert len(result) == 3
        assert all(r.status == "FAIL" for r in result)

    def test_break_glass_on_non_ga_role_fails(self):
        """FAIL for a break-glass user with standing assignment to a non-GA Tier 0 role."""
        bg_user_id = "break-glass-1"
        inst = _make_instance(
            principal_id=bg_user_id,
            role_definition_id=PRA_ROLE_ID,
            principal_display_name="BG1",
        )
        ca_policies = {
            "p1": _make_ca_policy(excluded_users=[bg_user_id]),
        }
        result = self._run(
            skus=[_p2_sku()],
            instances=[inst],
            conditional_access_policies=ca_policies,
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_configured_emergency_ids_pass(self):
        """PASS for explicitly configured emergency-access user IDs."""
        bg_user_id = "configured-bg-1"
        inst = _make_instance(
            principal_id=bg_user_id,
            principal_display_name="Configured BG",
        )
        result = self._run(
            skus=[_p2_sku()],
            instances=[inst],
            conditional_access_policies={},
            audit_config={"emergency_access_user_ids": [bg_user_id]},
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "emergency-access" in result[0].status_extended

    def test_configured_emergency_ids_with_ca_unavailable_pass(self):
        """PASS for configured emergency-access IDs even when CA policies are unavailable."""
        bg_user_id = "configured-bg-1"
        inst_bg = _make_instance(
            id="i-bg",
            principal_id=bg_user_id,
            principal_display_name="Configured BG",
            principal_upn="bg@contoso.com",
        )
        inst_regular = _make_instance(
            id="i-regular",
            principal_id="regular-user",
            principal_display_name="Regular User",
            principal_upn="regular@contoso.com",
        )
        result = self._run(
            skus=[_p2_sku()],
            instances=[inst_bg, inst_regular],
            conditional_access_policies=None,
            audit_config={"emergency_access_user_ids": [bg_user_id]},
        )
        assert len(result) == 2
        statuses = {r.resource_id: r.status for r in result}
        # Break-glass user still passes via configured IDs.
        assert statuses["i-bg"] == "PASS"
        # Regular user FAILs with the CA unavailable warning appended.
        assert statuses["i-regular"] == "FAIL"
        regular_finding = next(r for r in result if r.resource_id == "i-regular")
        assert (
            "emergency-access accounts could not be identified"
            in regular_finding.status_extended
        )

    # --- CA unavailable ---

    def test_ca_unavailable_appends_warning(self):
        """FAIL message includes warning when CA policies are unavailable."""
        inst = _make_instance()
        result = self._run(
            skus=[_p2_sku()],
            instances=[inst],
            conditional_access_policies=None,
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            "emergency-access accounts could not be identified"
            in result[0].status_extended
        )
        assert "Conditional Access policies unavailable" in result[0].status_extended

    # --- Filters ---

    def test_dir_sync_role_excluded(self):
        """Directory Synchronization Accounts role is excluded from evaluation."""
        inst = _make_instance(role_definition_id=DIR_SYNC_ROLE_ID)
        result = self._run(skus=[_p2_sku()], instances=[inst])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == "tier0RoleAssignments"

    def test_service_principal_excluded(self):
        """Service principals are out of scope."""
        inst = _make_instance(
            principal_odata_type="#microsoft.graph.servicePrincipal",
        )
        result = self._run(skus=[_p2_sku()], instances=[inst])
        assert len(result) == 1
        assert result[0].resource_id == "tier0RoleAssignments"

    def test_group_member_type_excluded(self):
        """memberType 'Group' is excluded (only 'Direct' evaluated)."""
        inst = _make_instance(member_type="Group")
        result = self._run(skus=[_p2_sku()], instances=[inst])
        assert len(result) == 1
        assert result[0].resource_id == "tier0RoleAssignments"

    def test_inherited_member_type_excluded(self):
        """memberType 'Inherited' is excluded (only 'Direct' evaluated)."""
        inst = _make_instance(member_type="Inherited")
        result = self._run(skus=[_p2_sku()], instances=[inst])
        assert len(result) == 1
        assert result[0].resource_id == "tier0RoleAssignments"

    def test_non_tier0_role_excluded(self):
        """Non-Tier 0 roles are not evaluated."""
        inst = _make_instance(
            role_definition_id="non-tier0-role-id",
        )
        result = self._run(skus=[_p2_sku()], instances=[inst])
        assert len(result) == 1
        assert result[0].resource_id == "tier0RoleAssignments"

    # --- Group assignment ---

    def test_group_standing_assignment_fails(self):
        """FAIL for a role-assignable group with a standing Tier 0 assignment."""
        inst = _make_instance(
            principal_odata_type="#microsoft.graph.group",
            principal_display_name="Admins Group",
            principal_upn=None,
        )
        result = self._run(skus=[_p2_sku()], instances=[inst])
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "Group" in result[0].status_extended
        # Groups should not have UPN in status_extended.
        assert "()" not in result[0].status_extended

    def test_group_not_eligible_for_break_glass_exception(self):
        """FAIL for a group even if it appears in break-glass exclusion set (break-glass is user-only)."""
        group_id = "group-bg"
        inst = _make_instance(
            principal_id=group_id,
            principal_odata_type="#microsoft.graph.group",
            principal_display_name="BG Group",
            principal_upn=None,
        )
        ca_policies = {
            "p1": _make_ca_policy(excluded_users=[group_id]),
        }
        result = self._run(
            skus=[_p2_sku()],
            instances=[inst],
            conditional_access_policies=ca_policies,
        )
        assert len(result) == 1
        # Groups cannot be break-glass because the check only allows
        # is_user=True for the exception.
        assert result[0].status == "FAIL"

    # --- Scoped assignments ---

    def test_au_scoped_assignment_evaluated(self):
        """Assignments scoped to an administrative unit are still evaluated."""
        inst = _make_instance(
            directory_scope_id="/administrativeUnits/au-123",
        )
        result = self._run(skus=[_p2_sku()], instances=[inst])
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "/administrativeUnits/au-123" in result[0].status_extended

    def test_tenant_wide_scope_displays_correctly(self):
        """directoryScopeId '/' is displayed as 'tenant-wide'."""
        inst = _make_instance(directory_scope_id="/")
        result = self._run(skus=[_p2_sku()], instances=[inst])
        assert len(result) == 1
        assert "tenant-wide" in result[0].status_extended
        assert result[0].status == "FAIL"

    # --- Mixed scenario ---

    def test_mixed_assignments(self):
        """Multiple instances with different outcomes."""
        instances = [
            # Activated -> PASS
            _make_instance(
                id="i-activated",
                principal_id="u1",
                assignment_type="Activated",
                principal_display_name="Bob Admin",
                end_date_time=datetime(2026, 10, 8, 11, 0, 0, tzinfo=timezone.utc),
            ),
            # Assigned non-BG -> FAIL
            _make_instance(
                id="i-assigned",
                principal_id="u2",
                assignment_type="Assigned",
                principal_display_name="Eve Admin",
                principal_upn="eve@contoso.com",
            ),
        ]
        result = self._run(skus=[_p2_sku()], instances=instances)
        assert len(result) == 2
        statuses = {r.resource_id: r.status for r in result}
        assert statuses["i-activated"] == "PASS"
        assert statuses["i-assigned"] == "FAIL"

    def test_mixed_with_break_glass_and_regular(self):
        """Break-glass GA passes while regular standing assignment fails in same run."""
        bg_id = "bg-user"
        regular_id = "regular-user"
        instances = [
            _make_instance(
                id="i-bg",
                principal_id=bg_id,
                principal_display_name="BG Account",
                principal_upn="bg@contoso.com",
                role_definition_id=GA_ROLE_ID,
            ),
            _make_instance(
                id="i-regular",
                principal_id=regular_id,
                principal_display_name="Regular Admin",
                principal_upn="admin@contoso.com",
                role_definition_id=GA_ROLE_ID,
            ),
        ]
        ca_policies = {
            "p1": _make_ca_policy(excluded_users=[bg_id]),
        }
        result = self._run(
            skus=[_p2_sku()],
            instances=instances,
            conditional_access_policies=ca_policies,
        )
        assert len(result) == 2
        statuses = {r.resource_id: r.status for r in result}
        assert statuses["i-bg"] == "PASS"
        assert statuses["i-regular"] == "FAIL"

    def test_only_excluded_filtered_instances_yields_tenant_pass(self):
        """PASS at tenant level when all instances are filtered out (SP + Dir Sync + non-Tier0)."""
        instances = [
            _make_instance(
                id="i-sp",
                principal_odata_type="#microsoft.graph.servicePrincipal",
            ),
            _make_instance(
                id="i-dirsync",
                role_definition_id=DIR_SYNC_ROLE_ID,
            ),
            _make_instance(
                id="i-non-tier0",
                role_definition_id="non-tier0-role-id",
            ),
            _make_instance(
                id="i-inherited",
                member_type="Inherited",
            ),
        ]
        result = self._run(skus=[_p2_sku()], instances=instances)
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == "tier0RoleAssignments"

    # --- Resource name format ---

    def test_resource_name_format(self):
        """Resource name follows '<display_name> - <role_name> (<scope>)'."""
        inst = _make_instance(
            principal_display_name="Alice Admin",
            role_definition_id=GA_ROLE_ID,
        )
        result = self._run(skus=[_p2_sku()], instances=[inst])
        assert len(result) == 1
        assert (
            result[0].resource_name
            == "Alice Admin - Global Administrator (tenant-wide)"
        )

    def test_resource_name_with_au_scope(self):
        """Resource name includes actual scope for non-tenant-wide assignments."""
        inst = _make_instance(
            principal_display_name="Scoped Admin",
            role_definition_id=PRA_ROLE_ID,
            directory_scope_id="/administrativeUnits/au-456",
        )
        result = self._run(skus=[_p2_sku()], instances=[inst])
        assert len(result) == 1
        assert (
            result[0].resource_name
            == "Scoped Admin - Privileged Role Administrator (/administrativeUnits/au-456)"
        )

    # --- Custom config: max_permanent_break_glass_global_admins ---

    def test_custom_max_break_glass_cap(self):
        """PASS when break-glass count is within a custom cap (e.g. 1)."""
        bg_id = "bg-user"
        inst = _make_instance(
            principal_id=bg_id,
            principal_display_name="BG Account",
        )
        ca_policies = {"p1": _make_ca_policy(excluded_users=[bg_id])}
        result = self._run(
            skus=[_p2_sku()],
            instances=[inst],
            conditional_access_policies=ca_policies,
            audit_config={"max_permanent_break_glass_global_admins": 1},
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "1 of 1 allowed" in result[0].status_extended

    def test_custom_max_break_glass_cap_exceeded(self):
        """FAIL when 2 break-glass users exceed a custom cap of 1."""
        bg1 = "bg-1"
        bg2 = "bg-2"
        instances = [
            _make_instance(id="i1", principal_id=bg1, principal_display_name="BG1"),
            _make_instance(id="i2", principal_id=bg2, principal_display_name="BG2"),
        ]
        ca_policies = {"p1": _make_ca_policy(excluded_users=[bg1, bg2])}
        result = self._run(
            skus=[_p2_sku()],
            instances=instances,
            conditional_access_policies=ca_policies,
            audit_config={"max_permanent_break_glass_global_admins": 1},
        )
        assert len(result) == 2
        assert all(r.status == "FAIL" for r in result)

    # --- User without UPN ---

    def test_user_without_upn(self):
        """FAIL message handles user with no UPN gracefully."""
        inst = _make_instance(
            principal_display_name="No UPN User",
            principal_upn=None,
        )
        result = self._run(skus=[_p2_sku()], instances=[inst])
        assert len(result) == 1
        assert result[0].status == "FAIL"
        # Should not contain empty parentheses "()" for missing UPN.
        assert "()" not in result[0].status_extended
        assert "No UPN User" in result[0].status_extended

    # --- Break-glass user with no UPN in PASS status ---

    def test_break_glass_without_upn_pass(self):
        """PASS message handles break-glass user without UPN."""
        bg_id = "bg-no-upn"
        inst = _make_instance(
            principal_id=bg_id,
            principal_display_name="BG No UPN",
            principal_upn=None,
        )
        ca_policies = {"p1": _make_ca_policy(excluded_users=[bg_id])}
        result = self._run(
            skus=[_p2_sku()],
            instances=[inst],
            conditional_access_policies=ca_policies,
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "emergency-access" in result[0].status_extended
        assert "()" not in result[0].status_extended

    # --- Multiple CA policies: user must be excluded from ALL enabled ---

    def test_user_excluded_from_only_some_ca_policies_not_break_glass(self):
        """FAIL when a user is excluded from some but not all enabled CA policies."""
        user_id = "partial-exclusion"
        inst = _make_instance(
            principal_id=user_id,
            principal_display_name="Partial Exclusion",
        )
        ca_policies = {
            "p1": _make_ca_policy(policy_id="p1", excluded_users=[user_id]),
            "p2": _make_ca_policy(policy_id="p2", excluded_users=[]),
        }
        result = self._run(
            skus=[_p2_sku()],
            instances=[inst],
            conditional_access_policies=ca_policies,
        )
        assert len(result) == 1
        # Not identified as break-glass -> FAIL.
        assert result[0].status == "FAIL"
