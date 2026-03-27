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
    UserAction,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_conditional_access_policy_device_registration_mfa_required.entra_conditional_access_policy_device_registration_mfa_required"


def build_policy(
    *,
    display_name: str,
    state: ConditionalAccessPolicyState,
    included_users: list[str] | None = None,
    included_user_actions: list[UserAction] | None = None,
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
                included_applications=[],
                excluded_applications=[],
                included_user_actions=included_user_actions or [],
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


class Test_entra_conditional_access_policy_device_registration_mfa_required:
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_device_registration_mfa_required.entra_conditional_access_policy_device_registration_mfa_required import (
                entra_conditional_access_policy_device_registration_mfa_required,
            )

            entra_client.conditional_access_policies = {}

            result = (
                entra_conditional_access_policy_device_registration_mfa_required().execute()
            )

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires MFA for device registration."
            )

    def test_enabled_policy_requires_mfa_for_device_registration(self):
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_device_registration_mfa_required.entra_conditional_access_policy_device_registration_mfa_required import (
                entra_conditional_access_policy_device_registration_mfa_required,
            )

            policy = build_policy(
                display_name="Device registration MFA",
                state=ConditionalAccessPolicyState.ENABLED,
                included_user_actions=[UserAction.REGISTER_DEVICE],
                built_in_controls=[ConditionalAccessGrantControl.MFA],
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = (
                entra_conditional_access_policy_device_registration_mfa_required().execute()
            )

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Conditional Access Policy 'Device registration MFA' enforces MFA for device registration."
            )
            assert result[0].resource_id == policy.id

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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_device_registration_mfa_required.entra_conditional_access_policy_device_registration_mfa_required import (
                entra_conditional_access_policy_device_registration_mfa_required,
            )

            policy = build_policy(
                display_name="Device registration MFA",
                state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                included_user_actions=[UserAction.REGISTER_DEVICE],
                built_in_controls=[ConditionalAccessGrantControl.MFA],
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = (
                entra_conditional_access_policy_device_registration_mfa_required().execute()
            )

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Conditional Access Policy 'Device registration MFA' reports MFA for device registration but does not enforce it."
            )

    def test_policy_not_targeting_all_users_fails(self):
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_device_registration_mfa_required.entra_conditional_access_policy_device_registration_mfa_required import (
                entra_conditional_access_policy_device_registration_mfa_required,
            )

            policy = build_policy(
                display_name="Scoped device registration MFA",
                state=ConditionalAccessPolicyState.ENABLED,
                included_users=[str(uuid4())],
                included_user_actions=[UserAction.REGISTER_DEVICE],
                built_in_controls=[ConditionalAccessGrantControl.MFA],
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = (
                entra_conditional_access_policy_device_registration_mfa_required().execute()
            )

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires MFA for device registration."
            )

    def test_policy_without_mfa_grant_control_fails(self):
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_device_registration_mfa_required.entra_conditional_access_policy_device_registration_mfa_required import (
                entra_conditional_access_policy_device_registration_mfa_required,
            )

            policy = build_policy(
                display_name="Device registration without MFA",
                state=ConditionalAccessPolicyState.ENABLED,
                included_user_actions=[UserAction.REGISTER_DEVICE],
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = (
                entra_conditional_access_policy_device_registration_mfa_required().execute()
            )

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires MFA for device registration."
            )
