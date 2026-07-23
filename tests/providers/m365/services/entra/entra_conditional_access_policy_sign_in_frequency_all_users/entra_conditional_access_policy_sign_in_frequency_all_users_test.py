from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    ApplicationsConditions,
    ConditionalAccessPolicy,
    ConditionalAccessPolicyState,
    Conditions,
    GrantControlOperator,
    GrantControls,
    PersistentBrowser,
    RiskLevel,
    SessionControls,
    SignInFrequency,
    SignInFrequencyInterval,
    SignInFrequencyType,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_conditional_access_policy_sign_in_frequency_all_users.entra_conditional_access_policy_sign_in_frequency_all_users"


def _make_policy(
    policy_id="policy-1",
    display_name="Sign-in Frequency",
    state=ConditionalAccessPolicyState.ENABLED,
    included_users=None,
    included_applications=None,
    is_enabled=True,
    frequency=1,
    freq_type=SignInFrequencyType.DAYS,
    interval=SignInFrequencyInterval.TIME_BASED,
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
        ),
        grant_controls=GrantControls(
            built_in_controls=[],
            operator=GrantControlOperator.AND,
            authentication_strength=None,
        ),
        session_controls=SessionControls(
            persistent_browser=PersistentBrowser(is_enabled=False, mode="always"),
            sign_in_frequency=SignInFrequency(
                is_enabled=is_enabled,
                frequency=frequency,
                type=freq_type,
                interval=interval,
            ),
        ),
        state=state,
    )


class Test_entra_conditional_access_policy_sign_in_frequency_all_users:
    def _run(self, policies):
        entra_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_sign_in_frequency_all_users.entra_conditional_access_policy_sign_in_frequency_all_users import (
                entra_conditional_access_policy_sign_in_frequency_all_users,
            )

            entra_client.conditional_access_policies = policies
            entra_client.tenant_domain = DOMAIN
            return (
                entra_conditional_access_policy_sign_in_frequency_all_users().execute()
            )

    def test_no_policies(self):
        result = self._run({})
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_policy_7_days(self):
        policy = _make_policy(frequency=7, freq_type=SignInFrequencyType.DAYS)
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_policy_every_time(self):
        policy = _make_policy(interval=SignInFrequencyInterval.EVERY_TIME)
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_policy_too_long(self):
        policy = _make_policy(frequency=30, freq_type=SignInFrequencyType.DAYS)
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_policy_disabled_frequency(self):
        policy = _make_policy(
            is_enabled=False, frequency=None, freq_type=None, interval=None
        )
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_policy_report_only(self):
        policy = _make_policy(state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING)
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "report-only mode" in result[0].status_extended

    def test_policy_risk_scoped_ignored(self):
        # A sign-in-frequency policy scoped only to risky sign-ins must not satisfy
        # the "all users" control.
        policy = _make_policy(frequency=1, freq_type=SignInFrequencyType.DAYS)
        policy.conditions.sign_in_risk_levels = [RiskLevel.HIGH]
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
