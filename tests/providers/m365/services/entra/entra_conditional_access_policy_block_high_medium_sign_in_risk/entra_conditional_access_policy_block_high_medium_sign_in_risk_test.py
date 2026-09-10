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

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_conditional_access_policy_block_high_medium_sign_in_risk.entra_conditional_access_policy_block_high_medium_sign_in_risk"


def _make_policy(
    policy_id="policy-1",
    display_name="Block Risky Sign-ins",
    state=ConditionalAccessPolicyState.ENABLED,
    included_users=None,
    included_applications=None,
    sign_in_risk_levels=None,
    built_in_controls=None,
):
    return ConditionalAccessPolicy(
        id=policy_id,
        display_name=display_name,
        conditions=Conditions(
            application_conditions=ApplicationsConditions(
                included_applications=included_applications or ["All"],
                excluded_applications=[],
                included_user_actions=[],
            ),
            user_conditions=UsersConditions(
                included_groups=[],
                excluded_groups=[],
                included_users=included_users or ["All"],
                excluded_users=[],
                included_roles=[],
                excluded_roles=[],
            ),
            client_app_types=[],
            sign_in_risk_levels=(
                sign_in_risk_levels
                if sign_in_risk_levels is not None
                else [RiskLevel.HIGH, RiskLevel.MEDIUM]
            ),
        ),
        grant_controls=GrantControls(
            built_in_controls=(
                built_in_controls
                if built_in_controls is not None
                else [ConditionalAccessGrantControl.BLOCK]
            ),
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


class Test_entra_conditional_access_policy_block_high_medium_sign_in_risk:
    def _run(self, policies):
        entra_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_block_high_medium_sign_in_risk.entra_conditional_access_policy_block_high_medium_sign_in_risk import (
                entra_conditional_access_policy_block_high_medium_sign_in_risk,
            )

            entra_client.conditional_access_policies = policies
            entra_client.tenant_domain = DOMAIN
            return (
                entra_conditional_access_policy_block_high_medium_sign_in_risk().execute()
            )

    def test_no_policies(self):
        result = self._run({})
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_policy_blocks_high_medium(self):
        policy = _make_policy()
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "Conditional Access Policy 'Block Risky Sign-ins' blocks high and medium sign-in risk."
        )

    def test_policy_only_high(self):
        policy = _make_policy(sign_in_risk_levels=[RiskLevel.HIGH])
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_policy_report_only(self):
        policy = _make_policy(state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING)
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
