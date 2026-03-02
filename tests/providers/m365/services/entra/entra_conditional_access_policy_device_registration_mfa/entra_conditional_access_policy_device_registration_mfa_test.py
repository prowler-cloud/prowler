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
    UserAction,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

INTUNE_ENROLLMENT_APP_ID = "d4ebce55-015a-49b5-a083-c84d1797ae8c"
MICROSOFT_INTUNE_APP_ID = "0000000a-0000-0000-c000-000000000000"

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_conditional_access_policy_device_registration_mfa.entra_conditional_access_policy_device_registration_mfa"


class Test_entra_conditional_access_policy_device_registration_mfa:
    def test_no_conditional_access_policies(self):
        """Test FAIL when there are no Conditional Access policies."""
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_device_registration_mfa.entra_conditional_access_policy_device_registration_mfa import (
                entra_conditional_access_policy_device_registration_mfa,
            )

            entra_client.conditional_access_policies = {}

            check = entra_conditional_access_policy_device_registration_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Conditional Access Policy gap: no policy requires MFA for device registration; no policy requires MFA with Every Time sign-in frequency for Intune enrollment."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_policy_disabled(self):
        """Test FAIL when all matching policies are disabled."""
        device_reg_id = str(uuid4())
        intune_id = str(uuid4())
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_device_registration_mfa.entra_conditional_access_policy_device_registration_mfa import (
                entra_conditional_access_policy_device_registration_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                device_reg_id: ConditionalAccessPolicy(
                    id=device_reg_id,
                    display_name="Device Reg MFA",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[],
                            excluded_applications=[],
                            included_user_actions=[UserAction.REGISTER_DEVICE],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=False,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.DISABLED,
                ),
                intune_id: ConditionalAccessPolicy(
                    id=intune_id,
                    display_name="Intune Enrollment MFA",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[INTUNE_ENROLLMENT_APP_ID],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.DISABLED,
                ),
            }

            check = entra_conditional_access_policy_device_registration_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_only_device_reg_mfa_enforced(self):
        """Test FAIL when only device registration MFA is enforced but Intune enrollment is missing."""
        device_reg_id = str(uuid4())
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_device_registration_mfa.entra_conditional_access_policy_device_registration_mfa import (
                entra_conditional_access_policy_device_registration_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                device_reg_id: ConditionalAccessPolicy(
                    id=device_reg_id,
                    display_name="Device Reg MFA",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[],
                            excluded_applications=[],
                            included_user_actions=[UserAction.REGISTER_DEVICE],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=False,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
            }

            check = entra_conditional_access_policy_device_registration_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "no policy requires MFA with Every Time sign-in frequency for Intune enrollment"
                in result[0].status_extended
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_only_intune_mfa_enforced(self):
        """Test FAIL when only Intune enrollment MFA is enforced but device registration is missing."""
        intune_id = str(uuid4())
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_device_registration_mfa.entra_conditional_access_policy_device_registration_mfa import (
                entra_conditional_access_policy_device_registration_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                intune_id: ConditionalAccessPolicy(
                    id=intune_id,
                    display_name="Intune Enrollment MFA",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[INTUNE_ENROLLMENT_APP_ID],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
            }

            check = entra_conditional_access_policy_device_registration_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "no policy requires MFA for device registration"
                in result[0].status_extended
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_device_reg_reporting_only(self):
        """Test FAIL when device registration MFA policy is report-only and Intune is enforced."""
        device_reg_id = str(uuid4())
        intune_id = str(uuid4())
        device_reg_name = "Device Reg MFA Report-Only"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_device_registration_mfa.entra_conditional_access_policy_device_registration_mfa import (
                entra_conditional_access_policy_device_registration_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                device_reg_id: ConditionalAccessPolicy(
                    id=device_reg_id,
                    display_name=device_reg_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[],
                            excluded_applications=[],
                            included_user_actions=[UserAction.REGISTER_DEVICE],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=False,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                ),
                intune_id: ConditionalAccessPolicy(
                    id=intune_id,
                    display_name="Intune Enrollment MFA",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[INTUNE_ENROLLMENT_APP_ID],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
            }

            check = entra_conditional_access_policy_device_registration_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                f"policy '{device_reg_name}' reports MFA for device registration but does not enforce it"
                in result[0].status_extended
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_not_targeting_all_users(self):
        """Test FAIL when policies do not target all users."""
        device_reg_id = str(uuid4())
        intune_id = str(uuid4())
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_device_registration_mfa.entra_conditional_access_policy_device_registration_mfa import (
                entra_conditional_access_policy_device_registration_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                device_reg_id: ConditionalAccessPolicy(
                    id=device_reg_id,
                    display_name="Device Reg MFA",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[],
                            excluded_applications=[],
                            included_user_actions=[UserAction.REGISTER_DEVICE],
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=[str(uuid4())],
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
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=False,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
                intune_id: ConditionalAccessPolicy(
                    id=intune_id,
                    display_name="Intune Enrollment MFA",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[INTUNE_ENROLLMENT_APP_ID],
                            excluded_applications=[],
                            included_user_actions=[],
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=[str(uuid4())],
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
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
            }

            check = entra_conditional_access_policy_device_registration_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_no_mfa_grant_control(self):
        """Test FAIL when policies exist but do not require MFA."""
        device_reg_id = str(uuid4())
        intune_id = str(uuid4())
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_device_registration_mfa.entra_conditional_access_policy_device_registration_mfa import (
                entra_conditional_access_policy_device_registration_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                device_reg_id: ConditionalAccessPolicy(
                    id=device_reg_id,
                    display_name="Device Reg No MFA",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[],
                            excluded_applications=[],
                            included_user_actions=[UserAction.REGISTER_DEVICE],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.COMPLIANT_DEVICE
                        ],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=False,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
                intune_id: ConditionalAccessPolicy(
                    id=intune_id,
                    display_name="Intune No MFA",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[INTUNE_ENROLLMENT_APP_ID],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.COMPLIANT_DEVICE
                        ],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
            }

            check = entra_conditional_access_policy_device_registration_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_intune_without_sign_in_frequency_every_time(self):
        """Test FAIL when Intune enrollment policy has MFA but sign-in frequency is not Every Time."""
        device_reg_id = str(uuid4())
        intune_id = str(uuid4())
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_device_registration_mfa.entra_conditional_access_policy_device_registration_mfa import (
                entra_conditional_access_policy_device_registration_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
                SignInFrequencyType,
            )

            entra_client.conditional_access_policies = {
                device_reg_id: ConditionalAccessPolicy(
                    id=device_reg_id,
                    display_name="Device Reg MFA",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[],
                            excluded_applications=[],
                            included_user_actions=[UserAction.REGISTER_DEVICE],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=False,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
                intune_id: ConditionalAccessPolicy(
                    id=intune_id,
                    display_name="Intune Enrollment MFA",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[INTUNE_ENROLLMENT_APP_ID],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=4,
                            type=SignInFrequencyType.HOURS,
                            interval=SignInFrequencyInterval.TIME_BASED,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
            }

            check = entra_conditional_access_policy_device_registration_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "no policy requires MFA with Every Time sign-in frequency for Intune enrollment"
                in result[0].status_extended
            )
            assert result[0].resource == {}

    def test_intune_excluded_with_all_apps(self):
        """Test FAIL when policy targets All apps but Intune is explicitly excluded."""
        device_reg_id = str(uuid4())
        intune_id = str(uuid4())
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_device_registration_mfa.entra_conditional_access_policy_device_registration_mfa import (
                entra_conditional_access_policy_device_registration_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                device_reg_id: ConditionalAccessPolicy(
                    id=device_reg_id,
                    display_name="Device Reg MFA",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[],
                            excluded_applications=[],
                            included_user_actions=[UserAction.REGISTER_DEVICE],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=False,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
                intune_id: ConditionalAccessPolicy(
                    id=intune_id,
                    display_name="All Apps MFA",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["All"],
                            excluded_applications=[INTUNE_ENROLLMENT_APP_ID],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
            }

            check = entra_conditional_access_policy_device_registration_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "no policy requires MFA with Every Time sign-in frequency for Intune enrollment"
                in result[0].status_extended
            )

    def test_intune_reporting_only(self):
        """Test FAIL when Intune enrollment MFA policy is report-only and device registration is enforced."""
        device_reg_id = str(uuid4())
        intune_id = str(uuid4())
        intune_name = "Intune Enrollment MFA Report-Only"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_device_registration_mfa.entra_conditional_access_policy_device_registration_mfa import (
                entra_conditional_access_policy_device_registration_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                device_reg_id: ConditionalAccessPolicy(
                    id=device_reg_id,
                    display_name="Device Reg MFA",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[],
                            excluded_applications=[],
                            included_user_actions=[UserAction.REGISTER_DEVICE],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=False,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
                intune_id: ConditionalAccessPolicy(
                    id=intune_id,
                    display_name=intune_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[INTUNE_ENROLLMENT_APP_ID],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                ),
            }

            check = entra_conditional_access_policy_device_registration_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                f"policy '{intune_name}' reports MFA for Intune enrollment but does not enforce it"
                in result[0].status_extended
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_both_reporting_only(self):
        """Test FAIL when both device registration and Intune enrollment policies are report-only."""
        device_reg_id = str(uuid4())
        intune_id = str(uuid4())
        device_reg_name = "Device Reg MFA Report-Only"
        intune_name = "Intune Enrollment MFA Report-Only"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_device_registration_mfa.entra_conditional_access_policy_device_registration_mfa import (
                entra_conditional_access_policy_device_registration_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                device_reg_id: ConditionalAccessPolicy(
                    id=device_reg_id,
                    display_name=device_reg_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[],
                            excluded_applications=[],
                            included_user_actions=[UserAction.REGISTER_DEVICE],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=False,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                ),
                intune_id: ConditionalAccessPolicy(
                    id=intune_id,
                    display_name=intune_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[INTUNE_ENROLLMENT_APP_ID],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                ),
            }

            check = entra_conditional_access_policy_device_registration_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                f"policy '{device_reg_name}' reports MFA for device registration but does not enforce it"
                in result[0].status_extended
            )
            assert (
                f"policy '{intune_name}' reports MFA for Intune enrollment but does not enforce it"
                in result[0].status_extended
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_intune_sign_in_frequency_disabled(self):
        """Test FAIL when Intune enrollment policy has correct interval but sign-in frequency is disabled."""
        device_reg_id = str(uuid4())
        intune_id = str(uuid4())
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_device_registration_mfa.entra_conditional_access_policy_device_registration_mfa import (
                entra_conditional_access_policy_device_registration_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                device_reg_id: ConditionalAccessPolicy(
                    id=device_reg_id,
                    display_name="Device Reg MFA",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[],
                            excluded_applications=[],
                            included_user_actions=[UserAction.REGISTER_DEVICE],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=False,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
                intune_id: ConditionalAccessPolicy(
                    id=intune_id,
                    display_name="Intune Enrollment MFA",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[INTUNE_ENROLLMENT_APP_ID],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=False,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
            }

            check = entra_conditional_access_policy_device_registration_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "no policy requires MFA with Every Time sign-in frequency for Intune enrollment"
                in result[0].status_extended
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_both_enforced_with_specific_intune_app(self):
        """Test PASS when both device registration and Intune enrollment MFA are enforced."""
        device_reg_id = str(uuid4())
        intune_id = str(uuid4())
        device_reg_name = "Device Reg MFA"
        intune_name = "Intune Enrollment MFA"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_device_registration_mfa.entra_conditional_access_policy_device_registration_mfa import (
                entra_conditional_access_policy_device_registration_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                device_reg_id: ConditionalAccessPolicy(
                    id=device_reg_id,
                    display_name=device_reg_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[],
                            excluded_applications=[],
                            included_user_actions=[UserAction.REGISTER_DEVICE],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=False,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
                intune_id: ConditionalAccessPolicy(
                    id=intune_id,
                    display_name=intune_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[INTUNE_ENROLLMENT_APP_ID],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
            }

            check = entra_conditional_access_policy_device_registration_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{device_reg_name}' enforces MFA for device registration and policy '{intune_name}' enforces MFA with Every Time sign-in frequency for Intune enrollment."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[device_reg_id].dict()
            )
            assert result[0].resource_name == device_reg_name
            assert result[0].resource_id == device_reg_id
            assert result[0].location == "global"

    def test_both_enforced_with_all_apps_for_intune(self):
        """Test PASS when Intune enrollment MFA is covered by an All apps policy."""
        device_reg_id = str(uuid4())
        intune_id = str(uuid4())
        device_reg_name = "Device Reg MFA"
        intune_name = "All Apps MFA Every Time"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_device_registration_mfa.entra_conditional_access_policy_device_registration_mfa import (
                entra_conditional_access_policy_device_registration_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                device_reg_id: ConditionalAccessPolicy(
                    id=device_reg_id,
                    display_name=device_reg_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[],
                            excluded_applications=[],
                            included_user_actions=[UserAction.REGISTER_DEVICE],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=False,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
                intune_id: ConditionalAccessPolicy(
                    id=intune_id,
                    display_name=intune_name,
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
                        user_risk_levels=[],
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
            }

            check = entra_conditional_access_policy_device_registration_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{device_reg_name}' enforces MFA for device registration and policy '{intune_name}' enforces MFA with Every Time sign-in frequency for Intune enrollment."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[device_reg_id].dict()
            )
            assert result[0].resource_name == device_reg_name
            assert result[0].resource_id == device_reg_id
            assert result[0].location == "global"

    def test_both_enforced_with_microsoft_intune_app_id(self):
        """Test PASS when Intune enrollment targets the Microsoft Intune app ID."""
        device_reg_id = str(uuid4())
        intune_id = str(uuid4())
        device_reg_name = "Device Reg MFA"
        intune_name = "Microsoft Intune MFA"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_device_registration_mfa.entra_conditional_access_policy_device_registration_mfa import (
                entra_conditional_access_policy_device_registration_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                device_reg_id: ConditionalAccessPolicy(
                    id=device_reg_id,
                    display_name=device_reg_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[],
                            excluded_applications=[],
                            included_user_actions=[UserAction.REGISTER_DEVICE],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=False,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
                intune_id: ConditionalAccessPolicy(
                    id=intune_id,
                    display_name=intune_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[MICROSOFT_INTUNE_APP_ID],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=None,
                            type=None,
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
            }

            check = entra_conditional_access_policy_device_registration_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{device_reg_name}' enforces MFA for device registration and policy '{intune_name}' enforces MFA with Every Time sign-in frequency for Intune enrollment."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[device_reg_id].dict()
            )
            assert result[0].resource_name == device_reg_name
            assert result[0].resource_id == device_reg_id
            assert result[0].location == "global"
