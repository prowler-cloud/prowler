from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    ApplicationsConditions,
    ConditionalAccessGrantControl,
    ConditionalAccessPolicy,
    ConditionalAccessPolicyState,
    Conditions,
    GrantControlOperator,
    GrantControls,
    PersistentBrowser,
    RiskLevel,
    SessionControls,
    SignInFrequency,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_conditional_access_policy_user_and_sign_in_risk_not_combined.entra_conditional_access_policy_user_and_sign_in_risk_not_combined"


def _make_policy(
    policy_id="policy-1",
    display_name="Risk Policy",
    state=ConditionalAccessPolicyState.ENABLED,
    user_risk_levels=None,
    sign_in_risk_levels=None,
):
    """Create a ConditionalAccessPolicy with the given risk levels."""
    return ConditionalAccessPolicy(
        id=policy_id,
        display_name=display_name,
        conditions=Conditions(
            application_conditions=ApplicationsConditions(
                included_applications=["All"],
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
            user_risk_levels=user_risk_levels or [],
            sign_in_risk_levels=sign_in_risk_levels or [],
        ),
        grant_controls=GrantControls(
            built_in_controls=[ConditionalAccessGrantControl.BLOCK],
            operator=GrantControlOperator.OR,
            authentication_strength=None,
        ),
        session_controls=SessionControls(
            persistent_browser=PersistentBrowser(is_enabled=False, mode="always"),
            sign_in_frequency=SignInFrequency(
                is_enabled=False, frequency=None, type=None, interval=None
            ),
        ),
        state=state,
    )


class Test_entra_conditional_access_policy_user_and_sign_in_risk_not_combined:
    """Tests for entra_conditional_access_policy_user_and_sign_in_risk_not_combined check."""

    def _run(self, policies, error=None):
        """Run the check with the given policies dict and optional read error."""
        entra_client = mock.MagicMock()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_user_and_sign_in_risk_not_combined.entra_conditional_access_policy_user_and_sign_in_risk_not_combined import (
                entra_conditional_access_policy_user_and_sign_in_risk_not_combined,
            )

            entra_client.conditional_access_policies = policies
            entra_client.conditional_access_policies_error = error
            entra_client.tenant_domain = DOMAIN
            return (
                entra_conditional_access_policy_user_and_sign_in_risk_not_combined().execute()
            )

    def test_read_error_returns_manual(self):
        """Policies could not be read; emit MANUAL."""
        result = self._run({}, error="ODataError: Forbidden")
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be read" in result[0].status_extended
        assert result[0].resource_id == "conditionalAccessPolicies"
        assert result[0].resource_name == "Conditional Access Policies"

    def test_no_policies_returns_pass(self):
        """A tenant without policies has no policy combining both risks."""
        result = self._run({})
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_policies_exist_but_none_use_risk_returns_pass(self):
        """Policies exist but none use risk conditions; tenant-level PASS."""
        policy = _make_policy(
            user_risk_levels=[],
            sign_in_risk_levels=[],
        )
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == "conditionalAccessPolicies"
        assert (
            "no policy combines user risk and sign-in risk" in result[0].status_extended
        )

    def test_policy_only_user_risk_pass(self):
        """Policy uses only user risk; PASS."""
        policy = _make_policy(
            display_name="User Risk Only",
            user_risk_levels=[RiskLevel.HIGH],
            sign_in_risk_levels=[],
        )
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == policy.id
        assert "configures user risk on its own" in result[0].status_extended

    def test_policy_only_sign_in_risk_pass(self):
        """Policy uses only sign-in risk; PASS."""
        policy = _make_policy(
            display_name="Sign-in Risk Only",
            user_risk_levels=[],
            sign_in_risk_levels=[RiskLevel.HIGH, RiskLevel.MEDIUM],
        )
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == policy.id
        assert "configures sign-in risk on its own" in result[0].status_extended

    def test_policy_combines_both_risks_fail(self):
        """Policy combines user risk and sign-in risk; FAIL."""
        policy = _make_policy(
            display_name="Combined Risk Policy",
            user_risk_levels=[RiskLevel.HIGH],
            sign_in_risk_levels=[RiskLevel.HIGH, RiskLevel.MEDIUM],
        )
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == policy.id
        assert "combines user risk" in result[0].status_extended
        assert "sign-in risk" in result[0].status_extended

    def test_policy_combines_both_risks_report_only_fail(self):
        """Report-only policy that combines both risks is also FAIL with annotation."""
        policy = _make_policy(
            display_name="Report-Only Combined",
            state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
            user_risk_levels=[RiskLevel.HIGH],
            sign_in_risk_levels=[RiskLevel.MEDIUM],
        )
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "(report-only)" in result[0].status_extended

    def test_disabled_policy_ignored(self):
        """Disabled policy that combines risks is ignored; tenant-level PASS."""
        no_risk_policy = _make_policy(
            policy_id="policy-no-risk",
            display_name="No Risk",
            user_risk_levels=[],
            sign_in_risk_levels=[],
        )
        disabled_combined = _make_policy(
            policy_id="policy-disabled",
            display_name="Disabled Combined",
            state=ConditionalAccessPolicyState.DISABLED,
            user_risk_levels=[RiskLevel.HIGH],
            sign_in_risk_levels=[RiskLevel.HIGH],
        )
        result = self._run(
            {
                no_risk_policy.id: no_risk_policy,
                disabled_combined.id: disabled_combined,
            }
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == "conditionalAccessPolicies"

    def test_multiple_policies_mixed(self):
        """Multiple policies: one correct, one combined; each gets a finding."""
        good_policy = _make_policy(
            policy_id="good",
            display_name="User Risk Only",
            user_risk_levels=[RiskLevel.HIGH],
            sign_in_risk_levels=[],
        )
        bad_policy = _make_policy(
            policy_id="bad",
            display_name="Combined Risk",
            user_risk_levels=[RiskLevel.HIGH],
            sign_in_risk_levels=[RiskLevel.HIGH, RiskLevel.MEDIUM],
        )
        result = self._run(
            {
                good_policy.id: good_policy,
                bad_policy.id: bad_policy,
            }
        )
        assert len(result) == 2
        statuses = {r.resource_id: r.status for r in result}
        assert statuses["good"] == "PASS"
        assert statuses["bad"] == "FAIL"
