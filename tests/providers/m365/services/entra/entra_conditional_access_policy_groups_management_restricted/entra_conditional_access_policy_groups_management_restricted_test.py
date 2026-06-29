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
    Group,
    PersistentBrowser,
    SessionControls,
    SignInFrequency,
    SignInFrequencyInterval,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE = (
    "prowler.providers.m365.services.entra."
    "entra_conditional_access_policy_groups_management_restricted."
    "entra_conditional_access_policy_groups_management_restricted.entra_client"
)


def _make_policy(
    included_groups=None,
    excluded_groups=None,
    state=ConditionalAccessPolicyState.ENABLED,
    display_name="Conditional Access Policy",
):
    return ConditionalAccessPolicy(
        id=str(uuid4()),
        display_name=display_name,
        conditions=Conditions(
            application_conditions=ApplicationsConditions(
                included_applications=["All"],
                excluded_applications=[],
                included_user_actions=[],
            ),
            user_conditions=UsersConditions(
                included_groups=included_groups or [],
                excluded_groups=excluded_groups or [],
                included_users=["All"],
                excluded_users=[],
                included_roles=[],
                excluded_roles=[],
            ),
            client_app_types=[],
            user_risk_levels=[],
        ),
        grant_controls=GrantControls(
            built_in_controls=[ConditionalAccessGrantControl.MFA],
            operator=GrantControlOperator.OR,
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
            application_enforced_restrictions=ApplicationEnforcedRestrictions(
                is_enabled=False
            ),
        ),
        state=state,
    )


def _entra_client_mock():
    client = mock.MagicMock()
    client.audited_tenant = "audited_tenant"
    client.audited_domain = DOMAIN
    client.groups = []
    client.conditional_access_policies = {}
    return client


class Test_entra_conditional_access_policy_groups_management_restricted:
    def test_no_enabled_or_report_only_policy_references_groups(self):
        entra_client = _entra_client_mock()
        entra_client.conditional_access_policies = {
            "policy-1": _make_policy(state=ConditionalAccessPolicyState.DISABLED)
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_groups_management_restricted.entra_conditional_access_policy_groups_management_restricted import (
                entra_conditional_access_policy_groups_management_restricted,
            )

            check = entra_conditional_access_policy_groups_management_restricted()
            result = check.execute()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "No enabled or report-only Conditional Access Policy references groups."
        )
        assert result[0].resource_id == "conditionalAccessPolicies"
        assert result[0].resource_name == "Conditional Access Policies"
        assert result[0].location == "global"

    def test_policy_without_user_conditions_is_treated_as_no_referenced_groups(self):
        entra_client = _entra_client_mock()
        policy = _make_policy(display_name="Policy Without User Conditions")
        policy.conditions.user_conditions = None
        entra_client.conditional_access_policies = {"policy-1": policy}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_groups_management_restricted.entra_conditional_access_policy_groups_management_restricted import (
                entra_conditional_access_policy_groups_management_restricted,
            )

            check = entra_conditional_access_policy_groups_management_restricted()
            result = check.execute()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "No enabled or report-only Conditional Access Policy references groups."
        )

    def test_all_referenced_groups_are_protected(self):
        entra_client = _entra_client_mock()
        entra_client.groups = [
            Group(
                id="group-1",
                name="Restricted Group",
                groupTypes=[],
                membershipRule=None,
                is_management_restricted=True,
            ),
            Group(
                id="group-2",
                name="Role Assignable Group",
                groupTypes=[],
                membershipRule=None,
                is_assignable_to_role=True,
            ),
        ]
        entra_client.conditional_access_policies = {
            "policy-1": _make_policy(
                included_groups=["group-1"],
                excluded_groups=["group-2"],
                display_name="Protected Policy",
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_groups_management_restricted.entra_conditional_access_policy_groups_management_restricted import (
                entra_conditional_access_policy_groups_management_restricted,
            )

            check = entra_conditional_access_policy_groups_management_restricted()
            result = check.execute()

        assert len(result) == 2
        assert {report.status for report in result} == {"PASS"}
        assert {report.resource_id for report in result} == {"group-1", "group-2"}
        for report in result:
            assert "is management-restricted or role-assignable" in (
                report.status_extended
            )

    def test_unprotected_group_fails_with_include_and_exclude_usage(self):
        entra_client = _entra_client_mock()
        entra_client.groups = [
            Group(
                id="group-1",
                name="Unprotected Group",
                groupTypes=[],
                membershipRule=None,
            )
        ]
        entra_client.conditional_access_policies = {
            "policy-1": _make_policy(
                included_groups=["group-1"],
                display_name="Include Policy",
            ),
            "policy-2": _make_policy(
                excluded_groups=["group-1"],
                state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                display_name="Report Only Exclusion Policy",
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_groups_management_restricted.entra_conditional_access_policy_groups_management_restricted import (
                entra_conditional_access_policy_groups_management_restricted,
            )

            check = entra_conditional_access_policy_groups_management_restricted()
            result = check.execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == "group-1"
        assert result[0].resource_name == "Unprotected Group"
        assert "Group Unprotected Group (group-1)" in result[0].status_extended
        assert (
            "neither management-restricted nor role-assignable"
            in result[0].status_extended
        )
        assert "include policies: Include Policy" in result[0].status_extended
        assert (
            "exclude policies: Report Only Exclusion Policy"
            in result[0].status_extended
        )

    def test_unresolved_group_reference_is_manual(self):
        entra_client = _entra_client_mock()
        entra_client.conditional_access_policies = {
            "policy-1": _make_policy(
                excluded_groups=["deleted-group"],
                display_name="Policy With Stale Group",
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_groups_management_restricted.entra_conditional_access_policy_groups_management_restricted import (
                entra_conditional_access_policy_groups_management_restricted,
            )

            check = entra_conditional_access_policy_groups_management_restricted()
            result = check.execute()

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == "deleted-group"
        assert "could not be resolved" in result[0].status_extended
        assert "exclude policies: Policy With Stale Group" in result[0].status_extended
