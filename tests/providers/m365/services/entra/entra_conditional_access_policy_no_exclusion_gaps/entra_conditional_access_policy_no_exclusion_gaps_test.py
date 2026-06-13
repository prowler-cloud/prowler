from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    ApplicationsConditions,
    ConditionalAccessGrantControl,
    ConditionalAccessPolicy,
    ConditionalAccessPolicyState,
    Conditions,
    GrantControlOperator,
    GrantControls,
    PersistentBrowser,
    PlatformConditions,
    SessionControls,
    SignInFrequency,
    SignInFrequencyInterval,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_PATH = "prowler.providers.m365.services.entra.entra_conditional_access_policy_no_exclusion_gaps.entra_conditional_access_policy_no_exclusion_gaps"
DIRECTORY_SYNC_ROLE_TEMPLATE_ID = "d29b2b05-8046-44ba-8758-1e26182fcf32"


def _policy(
    display_name="Policy",
    state=ConditionalAccessPolicyState.ENABLED,
    included_users=None,
    excluded_users=None,
    included_groups=None,
    excluded_groups=None,
    included_roles=None,
    excluded_roles=None,
    included_applications=None,
    excluded_applications=None,
    include_platforms=None,
    exclude_platforms=None,
    block=False,
):
    """Build a fully-populated ConditionalAccessPolicy for tests."""
    return ConditionalAccessPolicy(
        id=str(uuid4()),
        display_name=display_name,
        conditions=Conditions(
            application_conditions=ApplicationsConditions(
                included_applications=included_applications or [],
                excluded_applications=excluded_applications or [],
                included_user_actions=[],
            ),
            user_conditions=UsersConditions(
                included_groups=included_groups or [],
                excluded_groups=excluded_groups or [],
                included_users=included_users or [],
                excluded_users=excluded_users or [],
                included_roles=included_roles or [],
                excluded_roles=excluded_roles or [],
            ),
            platform_conditions=PlatformConditions(
                include_platforms=include_platforms or [],
                exclude_platforms=exclude_platforms or [],
            ),
        ),
        grant_controls=GrantControls(
            built_in_controls=(
                [ConditionalAccessGrantControl.BLOCK]
                if block
                else [ConditionalAccessGrantControl.MFA]
            ),
            operator=GrantControlOperator.AND,
            authentication_strength=None,
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
        state=state,
    )


def _run(policies):
    """Run the check with a mocked entra_client holding the given policies."""
    entra_client = mock.MagicMock
    entra_client.audited_tenant = "audited_tenant"
    entra_client.audited_domain = DOMAIN
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_m365_provider(),
        ),
        mock.patch(f"{CHECK_PATH}.entra_client", new=entra_client),
    ):
        from prowler.providers.m365.services.entra.entra_conditional_access_policy_no_exclusion_gaps.entra_conditional_access_policy_no_exclusion_gaps import (
            entra_conditional_access_policy_no_exclusion_gaps,
        )

        entra_client.conditional_access_policies = {p.id: p for p in policies}
        check = entra_conditional_access_policy_no_exclusion_gaps()
        return check.execute()


class Test_entra_conditional_access_policy_no_exclusion_gaps:
    def test_no_policies(self):
        result = _run([])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "No enabled Conditional Access policies" in result[0].status_extended
        assert result[0].resource == {}
        assert result[0].resource_name == "Conditional Access Policies"
        assert result[0].resource_id == "conditionalAccessPolicies"
        assert result[0].location == "global"

    def test_only_disabled_policies(self):
        result = _run(
            [
                _policy(
                    state=ConditionalAccessPolicyState.DISABLED,
                    included_users=["All"],
                    excluded_users=["user-1"],
                )
            ]
        )
        assert result[0].status == "PASS"
        assert "No enabled Conditional Access policies" in result[0].status_extended

    def test_report_only_policies_out_of_scope(self):
        # An exclusion in a report-only policy must not be evaluated.
        result = _run(
            [
                _policy(
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                    included_users=["All"],
                    excluded_users=["orphan-user"],
                )
            ]
        )
        assert result[0].status == "PASS"
        assert "No enabled Conditional Access policies" in result[0].status_extended

    def test_no_exclusions_used(self):
        result = _run([_policy(included_users=["All"], included_applications=["All"])])
        assert result[0].status == "PASS"
        assert "no coverage gaps are possible" in result[0].status_extended

    def test_exclusion_covered_by_another_policy(self):
        # Policy A excludes user-1; Policy B includes user-1 explicitly -> covered.
        result = _run(
            [
                _policy(display_name="A", included_users=["All"], excluded_users=["user-1"]),
                _policy(display_name="B", included_users=["user-1"]),
            ]
        )
        assert result[0].status == "PASS"
        assert "covered by an include condition" in result[0].status_extended

    def test_user_exclusion_gap(self):
        # user-1 is excluded but never included anywhere -> FAIL.
        result = _run(
            [_policy(display_name="A", included_users=["All"], excluded_users=["user-1"])]
        )
        assert result[0].status == "FAIL"
        assert "users: user-1" in result[0].status_extended
        assert "excluded by: A" in result[0].status_extended

    def test_group_and_role_gaps_reported_by_type(self):
        result = _run(
            [
                _policy(
                    display_name="P",
                    included_users=["All"],
                    excluded_groups=["group-x"],
                    excluded_roles=["role-y"],
                )
            ]
        )
        assert result[0].status == "FAIL"
        assert "groups: group-x" in result[0].status_extended
        assert "roles: role-y" in result[0].status_extended

    def test_application_exclusion_gap(self):
        result = _run(
            [
                _policy(
                    display_name="AppPolicy",
                    included_applications=["All"],
                    excluded_applications=["app-123"],
                )
            ]
        )
        assert result[0].status == "FAIL"
        assert "applications: app-123" in result[0].status_extended

    def test_application_exclusion_covered(self):
        result = _run(
            [
                _policy(
                    display_name="A",
                    included_applications=["All"],
                    excluded_applications=["app-123"],
                ),
                _policy(display_name="B", included_applications=["app-123"]),
            ]
        )
        assert result[0].status == "PASS"

    def test_platform_exclusion_gap(self):
        result = _run(
            [
                _policy(
                    display_name="PlatPolicy",
                    included_users=["All"],
                    exclude_platforms=["android"],
                )
            ]
        )
        assert result[0].status == "FAIL"
        assert "platforms: android" in result[0].status_extended

    def test_directory_sync_role_exclusion_skipped(self):
        # Dir-sync role excluded with no fallback must NOT be a gap.
        result = _run(
            [
                _policy(
                    display_name="P",
                    included_users=["All"],
                    excluded_roles=[DIRECTORY_SYNC_ROLE_TEMPLATE_ID],
                )
            ]
        )
        assert result[0].status == "PASS"
        assert "covered by an include condition" in result[0].status_extended

    def test_emergency_access_user_exclusion_skipped(self):
        # A break-glass user excluded from EVERY enabled blocking policy is an
        # intended gap and must not be reported.
        emergency = "breakglass-user"
        result = _run(
            [
                _policy(
                    display_name="Block1",
                    block=True,
                    included_users=["All"],
                    excluded_users=[emergency],
                ),
                _policy(
                    display_name="Block2",
                    block=True,
                    included_users=["All"],
                    excluded_users=[emergency],
                ),
            ]
        )
        assert result[0].status == "PASS"
        assert "covered by an include condition" in result[0].status_extended

    def test_mixed_gap_and_covered(self):
        # user-1 covered, user-2 orphaned -> FAIL listing only user-2.
        result = _run(
            [
                _policy(
                    display_name="A",
                    included_users=["All"],
                    excluded_users=["user-1", "user-2"],
                ),
                _policy(display_name="B", included_users=["user-1"]),
            ]
        )
        assert result[0].status == "FAIL"
        assert "user-2" in result[0].status_extended
        assert "users: user-1 " not in result[0].status_extended
