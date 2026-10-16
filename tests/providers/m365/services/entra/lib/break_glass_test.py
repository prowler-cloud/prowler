"""Tests for the break-glass identification helper."""

from prowler.providers.m365.services.entra.entra_service import (
    ApplicationsConditions,
    Conditions,
    ConditionalAccessPolicy,
    ConditionalAccessPolicyState,
    GrantControlOperator,
    GrantControls,
    PersistentBrowser,
    SessionControls,
    SignInFrequency,
    SignInFrequencyInterval,
    UsersConditions,
)
from prowler.providers.m365.services.entra.lib.break_glass import (
    identify_break_glass_user_ids,
)


def _make_ca_policy(policy_id, excluded_users, state="enabled"):
    """Build a minimal CA policy for testing."""
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
                excluded_users=excluded_users,
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


class Test_identify_break_glass_user_ids:
    """Tests for the break-glass identification heuristic."""

    def test_none_policies_returns_none(self):
        """Return None when CA policies are unavailable."""
        assert identify_break_glass_user_ids(None) is None

    def test_empty_policies_returns_empty(self):
        """Return empty set when no policies exist."""
        result = identify_break_glass_user_ids({})
        assert result == set()

    def test_no_enabled_policies(self):
        """Return empty set when all policies are disabled."""
        policies = {
            "p1": _make_ca_policy("p1", ["user-1"], state="disabled"),
        }
        result = identify_break_glass_user_ids(policies)
        assert result == set()

    def test_user_excluded_from_all_policies(self):
        """Identify a user excluded from all enabled policies."""
        policies = {
            "p1": _make_ca_policy("p1", ["bg-user"]),
            "p2": _make_ca_policy("p2", ["bg-user", "other"]),
        }
        result = identify_break_glass_user_ids(policies)
        assert "bg-user" in result
        assert "other" not in result

    def test_user_not_excluded_from_all_policies(self):
        """Do not identify a user excluded from only some policies."""
        policies = {
            "p1": _make_ca_policy("p1", ["user-1"]),
            "p2": _make_ca_policy("p2", []),
        }
        result = identify_break_glass_user_ids(policies)
        assert "user-1" not in result

    def test_configured_ids_merged(self):
        """Explicitly configured IDs are merged with heuristic results."""
        policies = {
            "p1": _make_ca_policy("p1", ["heuristic-bg"]),
        }
        result = identify_break_glass_user_ids(
            policies, configured_emergency_user_ids=["explicit-bg"]
        )
        assert "heuristic-bg" in result
        assert "explicit-bg" in result

    def test_configured_ids_only_when_no_heuristic(self):
        """Return only configured IDs when no heuristic match."""
        result = identify_break_glass_user_ids(
            {}, configured_emergency_user_ids=["explicit-bg"]
        )
        assert result == {"explicit-bg"}

    def test_configured_ids_with_none_policies(self):
        """Return None even with configured IDs when policies unavailable."""
        result = identify_break_glass_user_ids(
            None, configured_emergency_user_ids=["explicit-bg"]
        )
        assert result is None
