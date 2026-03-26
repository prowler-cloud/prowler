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
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

INTUNE_ENROLLMENT_APP_ID = "d4ebce55-015a-49b5-a083-c84d1797ae8c"
MICROSOFT_INTUNE_APP_ID = "0000000a-0000-0000-c000-000000000000"
CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_conditional_access_policy_intune_enrollment_mfa.entra_conditional_access_policy_intune_enrollment_mfa"


def build_policy(
    *,
    display_name: str,
    state: ConditionalAccessPolicyState,
    included_users: list[str] | None = None,
    included_applications: list[str] | None = None,
    excluded_applications: list[str] | None = None,
    built_in_controls: list[ConditionalAccessGrantControl] | None = None,
):
    from prowler.providers.m365.services.entra.entra_service import (
        ConditionalAccessPolicy,
    )

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
                included_groups=[],
                excluded_groups=[],
                included_users=included_users or ["All"],
                excluded_users=[],
                included_roles=[],
                excluded_roles=[],
            ),
            client_app_types=[],
            user_risk_levels=[],
        ),
        grant_controls=GrantControls(
            built_in_controls=built_in_controls or [],
            operator=GrantControlOperator.OR,
            authentication_strength=None,
        ),
        session_controls=SessionControls(
            persistent_browser=PersistentBrowser(is_enabled=False, mode="always"),
            sign_in_frequency=SignInFrequency(
                is_enabled=False,
                frequency=None,
                type=None,
                interval=None,
            ),
        ),
        state=state,
    )


class Test_entra_conditional_access_policy_intune_enrollment_mfa:
    def test_no_conditional_access_policies(self):
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_intune_enrollment_mfa.entra_conditional_access_policy_intune_enrollment_mfa import (
                entra_conditional_access_policy_intune_enrollment_mfa,
            )

            entra_client.conditional_access_policies = {}

            result = entra_conditional_access_policy_intune_enrollment_mfa().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires MFA for Intune enrollment."
            )

    def test_enabled_policy_requires_mfa_for_intune_enrollment(self):
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_intune_enrollment_mfa.entra_conditional_access_policy_intune_enrollment_mfa import (
                entra_conditional_access_policy_intune_enrollment_mfa,
            )

            policy = build_policy(
                display_name="Intune enrollment MFA",
                state=ConditionalAccessPolicyState.ENABLED,
                included_applications=[INTUNE_ENROLLMENT_APP_ID],
                built_in_controls=[ConditionalAccessGrantControl.MFA],
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = entra_conditional_access_policy_intune_enrollment_mfa().execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Conditional Access Policy 'Intune enrollment MFA' enforces MFA for Intune enrollment."
            )

    def test_enabled_policy_with_microsoft_intune_app_id_passes(self):
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_intune_enrollment_mfa.entra_conditional_access_policy_intune_enrollment_mfa import (
                entra_conditional_access_policy_intune_enrollment_mfa,
            )

            policy = build_policy(
                display_name="Microsoft Intune MFA",
                state=ConditionalAccessPolicyState.ENABLED,
                included_applications=[MICROSOFT_INTUNE_APP_ID],
                built_in_controls=[ConditionalAccessGrantControl.MFA],
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = entra_conditional_access_policy_intune_enrollment_mfa().execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Conditional Access Policy 'Microsoft Intune MFA' enforces MFA for Intune enrollment."
            )

    def test_reporting_only_policy_fails(self):
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_intune_enrollment_mfa.entra_conditional_access_policy_intune_enrollment_mfa import (
                entra_conditional_access_policy_intune_enrollment_mfa,
            )

            policy = build_policy(
                display_name="Intune enrollment MFA",
                state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                included_applications=[INTUNE_ENROLLMENT_APP_ID],
                built_in_controls=[ConditionalAccessGrantControl.MFA],
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = entra_conditional_access_policy_intune_enrollment_mfa().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Conditional Access Policy 'Intune enrollment MFA' reports MFA for Intune enrollment but does not enforce it."
            )

    def test_policy_excluding_intune_fails(self):
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_intune_enrollment_mfa.entra_conditional_access_policy_intune_enrollment_mfa import (
                entra_conditional_access_policy_intune_enrollment_mfa,
            )

            policy = build_policy(
                display_name="All apps except Intune",
                state=ConditionalAccessPolicyState.ENABLED,
                included_applications=["All"],
                excluded_applications=[INTUNE_ENROLLMENT_APP_ID],
                built_in_controls=[ConditionalAccessGrantControl.MFA],
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = entra_conditional_access_policy_intune_enrollment_mfa().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires MFA for Intune enrollment."
            )
