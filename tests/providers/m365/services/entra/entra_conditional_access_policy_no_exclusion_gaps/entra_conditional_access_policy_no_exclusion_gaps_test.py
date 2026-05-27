"""Tests for entra_conditional_access_policy_no_exclusion_gaps."""

from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    ApplicationEnforcedRestrictions,
    ApplicationsConditions,
    ConditionalAccessGrantControl,
    ConditionalAccessPolicy,
    ConditionalAccessPolicyState,
    Conditions,
    GrantControlOperator,
    GrantControls,
    PersistentBrowser,
    SessionControls,
    SignInFrequency,
    SignInFrequencyInterval,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

DIRECTORY_SYNC_ROLE = "d29b2b05-8046-44ba-8758-1e26182fcf32"

CHECK_MODULE = (
    "prowler.providers.m365.services.entra"
    ".entra_conditional_access_policy_no_exclusion_gaps"
    ".entra_conditional_access_policy_no_exclusion_gaps"
)


def _session_controls():
    return SessionControls(
        persistent_browser=PersistentBrowser(is_enabled=False, mode="always"),
        sign_in_frequency=SignInFrequency(
            is_enabled=False,
            frequency=None,
            type=None,
            interval=SignInFrequencyInterval.EVERY_TIME,
        ),
        application_enforced_restrictions=ApplicationEnforcedRestrictions(
            is_enabled=False
        ),
    )


def _mfa_grant():
    return GrantControls(
        built_in_controls=[ConditionalAccessGrantControl.MFA],
        operator=GrantControlOperator.AND,
        authentication_strength=None,
    )


def _block_grant():
    return GrantControls(
        built_in_controls=[ConditionalAccessGrantControl.BLOCK],
        operator=GrantControlOperator.AND,
        authentication_strength=None,
    )


def _policy(
    *,
    policy_id=None,
    display_name="Test Policy",
    included_users=None,
    excluded_users=None,
    included_groups=None,
    excluded_groups=None,
    included_roles=None,
    excluded_roles=None,
    included_apps=None,
    excluded_apps=None,
    state=ConditionalAccessPolicyState.ENABLED,
    grant=None,
):
    return ConditionalAccessPolicy(
        id=policy_id or str(uuid4()),
        display_name=display_name,
        conditions=Conditions(
            application_conditions=ApplicationsConditions(
                included_applications=included_apps or ["All"],
                excluded_applications=excluded_apps or [],
                included_user_actions=[],
            ),
            user_conditions=UsersConditions(
                included_users=included_users or ["All"],
                excluded_users=excluded_users or [],
                included_groups=included_groups or [],
                excluded_groups=excluded_groups or [],
                included_roles=included_roles or [],
                excluded_roles=excluded_roles or [],
            ),
            client_app_types=[],
            user_risk_levels=[],
        ),
        grant_controls=grant or _mfa_grant(),
        session_controls=_session_controls(),
        state=state,
    )


class Test_entra_conditional_access_policy_no_exclusion_gaps:
    def _run(self, policies: dict):
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.conditional_access_policies = policies
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_no_exclusion_gaps.entra_conditional_access_policy_no_exclusion_gaps import (
                entra_conditional_access_policy_no_exclusion_gaps,
            )

            check = entra_conditional_access_policy_no_exclusion_gaps()
            return check.execute()

    # -------------------------------------------------------------------------
    # Edge cases — nothing to evaluate
    # -------------------------------------------------------------------------

    def test_no_policies(self):
        result = self._run({})
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "No enabled Conditional Access policies found" in result[0].status_extended

    def test_all_policies_disabled(self):
        pid = str(uuid4())
        p = _policy(
            policy_id=pid,
            excluded_users=["user-abc"],
            state=ConditionalAccessPolicyState.DISABLED,
        )
        result = self._run({pid: p})
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "No enabled" in result[0].status_extended

    def test_report_only_policy_not_evaluated(self):
        """Report-only policies are excluded from both the include set and the exclusion check."""
        pid = str(uuid4())
        p = _policy(
            policy_id=pid,
            excluded_users=["user-xyz"],
            state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
        )
        result = self._run({pid: p})
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "No enabled" in result[0].status_extended

    def test_no_exclusions_in_any_policy(self):
        pid = str(uuid4())
        p = _policy(policy_id=pid)
        result = self._run({pid: p})
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "no exclusion" in result[0].status_extended.lower()

    # -------------------------------------------------------------------------
    # PASS scenarios
    # -------------------------------------------------------------------------

    def test_excluded_user_covered_by_another_policy(self):
        user_id = str(uuid4())
        broad_id = str(uuid4())
        targeted_id = str(uuid4())

        # Policy A: broad "All" policy that excludes user_id
        policy_a = _policy(
            policy_id=broad_id,
            display_name="Broad MFA",
            included_users=["All"],
            excluded_users=[user_id],
        )
        # Policy B: explicitly includes user_id
        policy_b = _policy(
            policy_id=targeted_id,
            display_name="Targeted user policy",
            included_users=[user_id],
        )
        result = self._run({broad_id: policy_a, targeted_id: policy_b})

        fail_results = [r for r in result if r.status == "FAIL"]
        assert not fail_results, f"Unexpected FAIL: {[r.status_extended for r in fail_results]}"

    def test_excluded_group_covered_by_another_policy(self):
        group_id = str(uuid4())
        broad_id = str(uuid4())
        targeted_id = str(uuid4())

        policy_a = _policy(
            policy_id=broad_id,
            display_name="Broad MFA",
            included_users=["All"],
            excluded_groups=[group_id],
        )
        policy_b = _policy(
            policy_id=targeted_id,
            display_name="Group policy",
            included_users=["All"],
            included_groups=[group_id],
        )
        result = self._run({broad_id: policy_a, targeted_id: policy_b})

        fail_results = [r for r in result if r.status == "FAIL"]
        assert not fail_results

    def test_excluded_role_covered_by_another_policy(self):
        role_id = str(uuid4())
        broad_id = str(uuid4())
        targeted_id = str(uuid4())

        policy_a = _policy(
            policy_id=broad_id,
            display_name="Broad MFA",
            included_users=["All"],
            excluded_roles=[role_id],
        )
        policy_b = _policy(
            policy_id=targeted_id,
            display_name="Admins policy",
            included_users=["All"],
            included_roles=[role_id],
        )
        result = self._run({broad_id: policy_a, targeted_id: policy_b})

        fail_results = [r for r in result if r.status == "FAIL"]
        assert not fail_results

    def test_directory_sync_role_excluded_always_passes(self):
        """The dir-sync role exclusion should never trigger a gap finding."""
        pid = str(uuid4())
        p = _policy(
            policy_id=pid,
            included_users=["All"],
            excluded_roles=[DIRECTORY_SYNC_ROLE],
        )
        result = self._run({pid: p})
        # dir-sync is the only exclusion; after stripping it, no exclusions remain
        assert all(r.status == "PASS" for r in result)

    def test_dir_sync_role_mixed_with_covered_role_passes(self):
        """Dir-sync role alongside another covered role should still pass."""
        role_id = str(uuid4())
        broad_id = str(uuid4())
        targeted_id = str(uuid4())

        policy_a = _policy(
            policy_id=broad_id,
            included_users=["All"],
            excluded_roles=[DIRECTORY_SYNC_ROLE, role_id],
        )
        policy_b = _policy(
            policy_id=targeted_id,
            included_users=["All"],
            included_roles=[role_id],
        )
        result = self._run({broad_id: policy_a, targeted_id: policy_b})
        fail_results = [r for r in result if r.status == "FAIL"]
        assert not fail_results

    def test_emergency_accounts_skipped(self):
        """Users excluded from all blocking policies are treated as emergency accounts."""
        emergency_user = str(uuid4())
        block_id = str(uuid4())

        # A single blocking policy excludes the emergency user.
        block_policy = _policy(
            policy_id=block_id,
            display_name="Block policy",
            included_users=["All"],
            excluded_users=[emergency_user],
            grant=_block_grant(),
        )
        result = self._run({block_id: block_policy})
        # emergency_user is excluded from all blocking policies → emergency account → skipped
        # After stripping, no effective exclusions remain → PASS
        assert all(r.status == "PASS" for r in result)

    def test_included_all_users_covers_excluded_users(self):
        """If the global include set contains 'All', any specific excluded user is covered."""
        user_id = str(uuid4())
        broad_id = str(uuid4())
        other_id = str(uuid4())

        # Policy A excludes user_id
        policy_a = _policy(
            policy_id=broad_id,
            display_name="Broad MFA",
            included_users=["All"],
            excluded_users=[user_id],
        )
        # Policy B also includes "All" without excluding user_id — user_id is covered
        policy_b = _policy(
            policy_id=other_id,
            display_name="Other policy",
            included_users=["All"],
        )
        result = self._run({broad_id: policy_a, other_id: policy_b})
        fail_results = [r for r in result if r.status == "FAIL"]
        assert not fail_results

    # -------------------------------------------------------------------------
    # FAIL scenarios
    # -------------------------------------------------------------------------

    def test_excluded_user_not_covered(self):
        user_id = str(uuid4())
        pid = str(uuid4())

        # Only policy excludes user_id; no other policy includes it.
        p = _policy(
            policy_id=pid,
            display_name="Broad MFA",
            included_users=["All"],
            excluded_users=[user_id],
        )
        result = self._run({pid: p})
        fail_results = [r for r in result if r.status == "FAIL"]
        assert len(fail_results) == 1
        assert "users" in fail_results[0].status_extended
        assert user_id in fail_results[0].status_extended
        assert fail_results[0].resource_id == pid

    def test_excluded_group_not_covered(self):
        group_id = str(uuid4())
        pid = str(uuid4())

        p = _policy(
            policy_id=pid,
            display_name="Broad MFA",
            included_users=["All"],
            excluded_groups=[group_id],
        )
        result = self._run({pid: p})
        fail_results = [r for r in result if r.status == "FAIL"]
        assert len(fail_results) == 1
        assert "groups" in fail_results[0].status_extended
        assert group_id in fail_results[0].status_extended

    def test_excluded_role_not_covered(self):
        role_id = str(uuid4())
        pid = str(uuid4())

        p = _policy(
            policy_id=pid,
            display_name="Broad MFA",
            included_users=["All"],
            excluded_roles=[role_id],
        )
        result = self._run({pid: p})
        fail_results = [r for r in result if r.status == "FAIL"]
        assert len(fail_results) == 1
        assert "roles" in fail_results[0].status_extended
        assert role_id in fail_results[0].status_extended

    def test_excluded_app_not_covered(self):
        app_id = str(uuid4())
        pid = str(uuid4())

        p = _policy(
            policy_id=pid,
            display_name="Broad App Policy",
            included_apps=["All"],
            excluded_apps=[app_id],
        )
        result = self._run({pid: p})
        fail_results = [r for r in result if r.status == "FAIL"]
        assert len(fail_results) == 1
        assert "apps" in fail_results[0].status_extended
        assert app_id in fail_results[0].status_extended

    def test_multiple_uncovered_object_types_reported_together(self):
        user_id = str(uuid4())
        group_id = str(uuid4())
        pid = str(uuid4())

        p = _policy(
            policy_id=pid,
            display_name="Complex Policy",
            included_users=["All"],
            excluded_users=[user_id],
            excluded_groups=[group_id],
        )
        result = self._run({pid: p})
        fail_results = [r for r in result if r.status == "FAIL"]
        assert len(fail_results) == 1
        ext = fail_results[0].status_extended
        assert user_id in ext
        assert group_id in ext

    def test_mixed_policies_pass_and_fail(self):
        covered_user = str(uuid4())
        uncovered_user = str(uuid4())
        pid_a = str(uuid4())
        pid_b = str(uuid4())
        pid_cover = str(uuid4())

        # Policy A excludes covered_user (will be covered by pid_cover)
        policy_a = _policy(
            policy_id=pid_a,
            display_name="Policy A",
            included_users=["All"],
            excluded_users=[covered_user],
        )
        # Policy B excludes uncovered_user (no other policy includes it)
        policy_b = _policy(
            policy_id=pid_b,
            display_name="Policy B",
            included_users=["All"],
            excluded_users=[uncovered_user],
        )
        # Covering policy: explicitly includes covered_user
        policy_cover = _policy(
            policy_id=pid_cover,
            display_name="Cover Policy",
            included_users=[covered_user],
        )
        result = self._run({pid_a: policy_a, pid_b: policy_b, pid_cover: policy_cover})

        pass_ids = {r.resource_id for r in result if r.status == "PASS"}
        fail_ids = {r.resource_id for r in result if r.status == "FAIL"}

        assert pid_a in pass_ids
        assert pid_b in fail_ids
        assert uncovered_user in next(
            r.status_extended for r in result if r.resource_id == pid_b
        )

    def test_only_dir_sync_exclusion_is_not_a_gap(self):
        """A policy whose only exclusion is the dir-sync role reports PASS."""
        another_role = str(uuid4())
        pid = str(uuid4())

        p = _policy(
            policy_id=pid,
            display_name="MFA all users",
            included_users=["All"],
            excluded_roles=[DIRECTORY_SYNC_ROLE],
        )
        result = self._run({pid: p})
        assert all(r.status == "PASS" for r in result)

    def test_dir_sync_plus_uncovered_role_fails(self):
        """If the dir-sync role is among the exclusions alongside an uncovered role, still FAIL."""
        uncovered_role = str(uuid4())
        pid = str(uuid4())

        p = _policy(
            policy_id=pid,
            display_name="MFA all users",
            included_users=["All"],
            excluded_roles=[DIRECTORY_SYNC_ROLE, uncovered_role],
        )
        result = self._run({pid: p})
        fail_results = [r for r in result if r.status == "FAIL"]
        assert len(fail_results) == 1
        assert uncovered_role in fail_results[0].status_extended
        assert DIRECTORY_SYNC_ROLE not in fail_results[0].status_extended
