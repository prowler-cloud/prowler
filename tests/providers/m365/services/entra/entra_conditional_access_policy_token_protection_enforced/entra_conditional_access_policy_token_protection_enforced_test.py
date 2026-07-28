from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    ApplicationsConditions,
    ClientAppType,
    ConditionalAccessPolicy,
    ConditionalAccessPolicyState,
    Conditions,
    GrantControlOperator,
    GrantControls,
    PersistentBrowser,
    PlatformConditions,
    SessionControls,
    SignInFrequency,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_conditional_access_policy_token_protection_enforced.entra_conditional_access_policy_token_protection_enforced"


def _make_policy(
    state=ConditionalAccessPolicyState.ENABLED,
    included_users=None,
    included_applications=None,
    include_platforms=None,
    client_app_types=None,
    secure_sign_in_session_enabled=True,
):
    return ConditionalAccessPolicy(
        id="policy-1",
        display_name="Token Protection",
        conditions=Conditions(
            application_conditions=ApplicationsConditions(
                included_applications=(
                    included_applications
                    if included_applications is not None
                    else ["All"]
                ),
                excluded_applications=[],
                included_user_actions=[],
            ),
            user_conditions=UsersConditions(
                included_groups=[],
                excluded_groups=[],
                included_users=(
                    included_users if included_users is not None else ["All"]
                ),
                excluded_users=[],
                included_roles=[],
                excluded_roles=[],
            ),
            client_app_types=(
                client_app_types
                if client_app_types is not None
                else [ClientAppType.MOBILE_APPS_AND_DESKTOP_CLIENTS]
            ),
            platform_conditions=PlatformConditions(
                include_platforms=(
                    include_platforms if include_platforms is not None else ["windows"]
                ),
                exclude_platforms=[],
            ),
        ),
        grant_controls=GrantControls(
            built_in_controls=[],
            operator=GrantControlOperator.AND,
            authentication_strength=None,
        ),
        session_controls=SessionControls(
            persistent_browser=PersistentBrowser(is_enabled=False, mode="always"),
            sign_in_frequency=SignInFrequency(
                is_enabled=False, frequency=None, type=None, interval=None
            ),
            secure_sign_in_session_enabled=secure_sign_in_session_enabled,
        ),
        state=state,
    )


class Test_entra_conditional_access_policy_token_protection_enforced:
    def _run(self, policies):
        entra_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_token_protection_enforced.entra_conditional_access_policy_token_protection_enforced import (
                entra_conditional_access_policy_token_protection_enforced,
            )

            entra_client.conditional_access_policies = policies
            entra_client.tenant_domain = DOMAIN
            return entra_conditional_access_policy_token_protection_enforced().execute()

    def test_no_policies(self):
        assert self._run({})[0].status == "FAIL"

    def test_token_protection_enforced(self):
        policy = _make_policy()
        result = self._run({policy.id: policy})
        assert result[0].status == "PASS"

    def test_token_protection_disabled(self):
        policy = _make_policy(secure_sign_in_session_enabled=False)
        result = self._run({policy.id: policy})
        assert result[0].status == "FAIL"

    def test_missing_windows_platform(self):
        policy = _make_policy(include_platforms=["macOS"])
        result = self._run({policy.id: policy})
        assert result[0].status == "FAIL"

    def test_browser_only_client(self):
        policy = _make_policy(client_app_types=[ClientAppType.BROWSER])
        result = self._run({policy.id: policy})
        assert result[0].status == "FAIL"

    def test_partial_app_coverage(self):
        policy = _make_policy(
            included_applications=["00000002-0000-0ff1-ce00-000000000000"]
        )
        result = self._run({policy.id: policy})
        assert result[0].status == "FAIL"

    def test_all_required_apps(self):
        policy = _make_policy(
            included_applications=[
                "00000002-0000-0ff1-ce00-000000000000",
                "00000003-0000-0ff1-ce00-000000000000",
                "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe",
            ]
        )
        result = self._run({policy.id: policy})
        assert result[0].status == "PASS"

    def test_report_only(self):
        policy = _make_policy(state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING)
        result = self._run({policy.id: policy})
        assert result[0].status == "FAIL"
