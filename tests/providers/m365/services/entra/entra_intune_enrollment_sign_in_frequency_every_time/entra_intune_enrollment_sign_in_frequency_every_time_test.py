from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    ApplicationEnforcedRestrictions,
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
    SignInFrequencyType,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_intune_enrollment_sign_in_frequency_every_time.entra_intune_enrollment_sign_in_frequency_every_time"
INTUNE_ENROLLMENT_APP_ID = "d4ebce55-015a-49b5-a083-c84d1797ae8c"
MICROSOFT_INTUNE_APP_ID = "0000000a-0000-0000-c000-000000000000"


def build_policy(
    *,
    display_name: str,
    state: ConditionalAccessPolicyState,
    included_users: list[str] | None = None,
    included_applications: list[str] | None = None,
    excluded_applications: list[str] | None = None,
    built_in_controls: list[ConditionalAccessGrantControl] | None = None,
    operator: GrantControlOperator = GrantControlOperator.OR,
    authentication_strength: str | None = None,
    sign_in_frequency_enabled: bool = True,
    sign_in_frequency_interval: (
        SignInFrequencyInterval | None
    ) = SignInFrequencyInterval.EVERY_TIME,
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
        ),
        grant_controls=GrantControls(
            built_in_controls=built_in_controls or [],
            operator=operator,
            authentication_strength=authentication_strength,
        ),
        session_controls=SessionControls(
            persistent_browser=PersistentBrowser(is_enabled=False, mode="always"),
            sign_in_frequency=SignInFrequency(
                is_enabled=sign_in_frequency_enabled,
                frequency=None,
                type=(
                    None
                    if sign_in_frequency_interval == SignInFrequencyInterval.EVERY_TIME
                    else SignInFrequencyType.HOURS
                ),
                interval=sign_in_frequency_interval,
            ),
            application_enforced_restrictions=ApplicationEnforcedRestrictions(
                is_enabled=False
            ),
        ),
        state=state,
    )


class Test_entra_intune_enrollment_sign_in_frequency_every_time:
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
            from prowler.providers.m365.services.entra.entra_intune_enrollment_sign_in_frequency_every_time.entra_intune_enrollment_sign_in_frequency_every_time import (
                entra_intune_enrollment_sign_in_frequency_every_time,
            )

            entra_client.conditional_access_policies = {}

            result = entra_intune_enrollment_sign_in_frequency_every_time().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires strong authentication and enforces Every Time sign-in frequency for Intune Enrollment."
            )

    def test_enabled_policy_requires_mfa_and_every_time(self):
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
            from prowler.providers.m365.services.entra.entra_intune_enrollment_sign_in_frequency_every_time.entra_intune_enrollment_sign_in_frequency_every_time import (
                entra_intune_enrollment_sign_in_frequency_every_time,
            )

            policy = build_policy(
                display_name="Intune Enrollment Every Time",
                state=ConditionalAccessPolicyState.ENABLED,
                included_applications=[INTUNE_ENROLLMENT_APP_ID],
                built_in_controls=[ConditionalAccessGrantControl.MFA],
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = entra_intune_enrollment_sign_in_frequency_every_time().execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Conditional Access Policy 'Intune Enrollment Every Time' requires strong authentication and enforces Every Time sign-in frequency for Intune Enrollment."
            )

    def test_enabled_policy_with_authentication_strength_passes(self):
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
            from prowler.providers.m365.services.entra.entra_intune_enrollment_sign_in_frequency_every_time.entra_intune_enrollment_sign_in_frequency_every_time import (
                entra_intune_enrollment_sign_in_frequency_every_time,
            )

            policy = build_policy(
                display_name="Intune Enrollment Auth Strength",
                state=ConditionalAccessPolicyState.ENABLED,
                included_applications=[INTUNE_ENROLLMENT_APP_ID],
                authentication_strength="Multifactor authentication",
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = entra_intune_enrollment_sign_in_frequency_every_time().execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Conditional Access Policy 'Intune Enrollment Auth Strength' requires strong authentication and enforces Every Time sign-in frequency for Intune Enrollment."
            )

    def test_policy_without_strong_auth_fails(self):
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
            from prowler.providers.m365.services.entra.entra_intune_enrollment_sign_in_frequency_every_time.entra_intune_enrollment_sign_in_frequency_every_time import (
                entra_intune_enrollment_sign_in_frequency_every_time,
            )

            policy = build_policy(
                display_name="Every Time Only",
                state=ConditionalAccessPolicyState.ENABLED,
                included_applications=[INTUNE_ENROLLMENT_APP_ID],
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = entra_intune_enrollment_sign_in_frequency_every_time().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires strong authentication and enforces Every Time sign-in frequency for Intune Enrollment."
            )

    def test_policy_without_every_time_fails(self):
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
            from prowler.providers.m365.services.entra.entra_intune_enrollment_sign_in_frequency_every_time.entra_intune_enrollment_sign_in_frequency_every_time import (
                entra_intune_enrollment_sign_in_frequency_every_time,
            )

            policy = build_policy(
                display_name="MFA Without Every Time",
                state=ConditionalAccessPolicyState.ENABLED,
                included_applications=[INTUNE_ENROLLMENT_APP_ID],
                built_in_controls=[ConditionalAccessGrantControl.MFA],
                sign_in_frequency_interval=SignInFrequencyInterval.TIME_BASED,
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = entra_intune_enrollment_sign_in_frequency_every_time().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires strong authentication and enforces Every Time sign-in frequency for Intune Enrollment."
            )

    def test_policy_with_microsoft_intune_app_id_fails(self):
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
            from prowler.providers.m365.services.entra.entra_intune_enrollment_sign_in_frequency_every_time.entra_intune_enrollment_sign_in_frequency_every_time import (
                entra_intune_enrollment_sign_in_frequency_every_time,
            )

            policy = build_policy(
                display_name="Microsoft Intune Policy",
                state=ConditionalAccessPolicyState.ENABLED,
                included_applications=[MICROSOFT_INTUNE_APP_ID],
                built_in_controls=[ConditionalAccessGrantControl.MFA],
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = entra_intune_enrollment_sign_in_frequency_every_time().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires strong authentication and enforces Every Time sign-in frequency for Intune Enrollment."
            )

    def test_policy_with_or_controls_does_not_require_mfa(self):
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
            from prowler.providers.m365.services.entra.entra_intune_enrollment_sign_in_frequency_every_time.entra_intune_enrollment_sign_in_frequency_every_time import (
                entra_intune_enrollment_sign_in_frequency_every_time,
            )

            policy = build_policy(
                display_name="Intune MFA or managed device",
                state=ConditionalAccessPolicyState.ENABLED,
                included_applications=[INTUNE_ENROLLMENT_APP_ID],
                built_in_controls=[
                    ConditionalAccessGrantControl.MFA,
                    ConditionalAccessGrantControl.DOMAIN_JOINED_DEVICE,
                ],
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = entra_intune_enrollment_sign_in_frequency_every_time().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires strong authentication and enforces Every Time sign-in frequency for Intune Enrollment."
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
            from prowler.providers.m365.services.entra.entra_intune_enrollment_sign_in_frequency_every_time.entra_intune_enrollment_sign_in_frequency_every_time import (
                entra_intune_enrollment_sign_in_frequency_every_time,
            )

            policy = build_policy(
                display_name="Intune Enrollment Report Only",
                state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                included_applications=[INTUNE_ENROLLMENT_APP_ID],
                built_in_controls=[ConditionalAccessGrantControl.MFA],
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = entra_intune_enrollment_sign_in_frequency_every_time().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Conditional Access Policy 'Intune Enrollment Report Only' reports strong authentication and Every Time sign-in frequency for Intune Enrollment but does not enforce them."
            )
