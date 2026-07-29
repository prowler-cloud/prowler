from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    ApplicationsConditions,
    ConditionalAccessGrantControl,
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

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_conditional_access_policy_explicitly_targets_azure_devops.entra_conditional_access_policy_explicitly_targets_azure_devops"

AZURE_DEVOPS_APP_ID = "499b84ac-1321-427f-aa17-267ca6975798"


def _make_session_controls():
    """Return default session controls for test policies."""
    return SessionControls(
        persistent_browser=PersistentBrowser(is_enabled=False, mode="always"),
        sign_in_frequency=SignInFrequency(
            is_enabled=False,
            frequency=None,
            type=None,
            interval=SignInFrequencyInterval.EVERY_TIME,
        ),
    )


def _make_conditions(included_applications=None):
    """Return Conditions with the given included applications."""
    return Conditions(
        application_conditions=ApplicationsConditions(
            included_applications=included_applications or ["All"],
            excluded_applications=[],
            included_user_actions=[],
        ),
        user_conditions=UsersConditions(
            included_groups=[],
            excluded_groups=[],
            included_users=["All"],
            excluded_users=[],
            included_roles=[],
            excluded_roles=[],
        ),
        client_app_types=[],
        user_risk_levels=[],
    )


def _make_grant_controls():
    """Return default grant controls for test policies."""
    return GrantControls(
        built_in_controls=[ConditionalAccessGrantControl.MFA],
        operator=GrantControlOperator.AND,
        authentication_strength=None,
    )


def _make_policy(state, included_applications=None, display_name="Azure DevOps Policy"):
    """Return a ConditionalAccessPolicy for tests."""
    from prowler.providers.m365.services.entra.entra_service import (
        ConditionalAccessPolicy,
    )

    return ConditionalAccessPolicy(
        id=str(uuid4()),
        display_name=display_name,
        conditions=_make_conditions(included_applications=included_applications),
        grant_controls=_make_grant_controls(),
        session_controls=_make_session_controls(),
        state=state,
    )


class Test_entra_conditional_access_policy_explicitly_targets_azure_devops:
    def _run_check(self, policies):
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_explicitly_targets_azure_devops.entra_conditional_access_policy_explicitly_targets_azure_devops import (
                entra_conditional_access_policy_explicitly_targets_azure_devops,
            )

            entra_client.conditional_access_policies = policies

            check = entra_conditional_access_policy_explicitly_targets_azure_devops()
            return check.execute()

    def test_no_conditional_access_policies(self):
        result = self._run_check({})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No enabled Conditional Access Policy explicitly targets Azure DevOps."
        )
        assert result[0].resource == {}
        assert result[0].resource_name == "Conditional Access Policies"
        assert result[0].resource_id == "conditionalAccessPolicies"
        assert result[0].location == "global"

    def test_enabled_policy_targets_azure_devops(self):
        policy = _make_policy(
            ConditionalAccessPolicyState.ENABLED,
            included_applications=[AZURE_DEVOPS_APP_ID],
        )
        result = self._run_check({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Conditional Access Policy {policy.display_name} explicitly targets Azure DevOps."
        )
        assert result[0].resource_name == policy.display_name
        assert result[0].resource_id == policy.id

    def test_enabled_policy_targets_all_apps_only(self):
        policy = _make_policy(
            ConditionalAccessPolicyState.ENABLED, included_applications=["All"]
        )
        result = self._run_check({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No enabled Conditional Access Policy explicitly targets Azure DevOps."
        )

    def test_disabled_policy_targets_azure_devops(self):
        policy = _make_policy(
            ConditionalAccessPolicyState.DISABLED,
            included_applications=[AZURE_DEVOPS_APP_ID],
        )
        result = self._run_check({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No enabled Conditional Access Policy explicitly targets Azure DevOps."
        )

    def test_report_only_policy_targets_azure_devops(self):
        policy = _make_policy(
            ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
            included_applications=[AZURE_DEVOPS_APP_ID],
        )
        result = self._run_check({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No enabled Conditional Access Policy explicitly targets Azure DevOps."
        )

    def test_multiple_policies_one_targets_azure_devops(self):
        non_matching = _make_policy(
            ConditionalAccessPolicyState.ENABLED,
            included_applications=["All"],
            display_name="All Apps Policy",
        )
        matching = _make_policy(
            ConditionalAccessPolicyState.ENABLED,
            included_applications=["some-other-app", AZURE_DEVOPS_APP_ID],
            display_name="Dedicated Azure DevOps Policy",
        )
        result = self._run_check({non_matching.id: non_matching, matching.id: matching})
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == matching.id
        assert (
            result[0].status_extended
            == f"Conditional Access Policy {matching.display_name} explicitly targets Azure DevOps."
        )
