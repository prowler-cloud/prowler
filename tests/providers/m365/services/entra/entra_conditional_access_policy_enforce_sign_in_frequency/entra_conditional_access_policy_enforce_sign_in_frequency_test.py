from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    ApplicationsConditions,
    ConditionalAccessPolicyState,
    Conditions,
    DeviceFilter,
    DeviceFilterMode,
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


class Test_entra_conditional_access_policy_enforce_sign_in_frequency:
    def test_entra_no_conditional_access_policies(self):
        """Test when no policies exist - should FAIL."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )

            entra_client.conditional_access_policies = {}

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces sign-in frequency for non-corporate devices."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_entra_policy_disabled(self):
        """Test when policy exists but is disabled - should FAIL."""
        policy_id = str(uuid4())
        display_name = "Test Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
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
                        user_risk_levels=[],
                        device_filter=DeviceFilter(
                            mode=DeviceFilterMode.INCLUDE,
                            rule='device.trustType -ne "ServerAD"',
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[],
                        operator=GrantControlOperator.AND,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=1,
                            type=SignInFrequencyType.HOURS,
                            interval=SignInFrequencyInterval.TIME_BASED,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.DISABLED,
                )
            }

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_policy_no_sign_in_frequency(self):
        """Test when policy has no sign-in frequency configured - should FAIL."""
        policy_id = str(uuid4())
        display_name = "Test Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
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
                        user_risk_levels=[],
                        device_filter=DeviceFilter(
                            mode=DeviceFilterMode.INCLUDE,
                            rule='device.trustType -ne "ServerAD"',
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[],
                        operator=GrantControlOperator.AND,
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
                            interval=SignInFrequencyInterval.TIME_BASED,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_policy_sign_in_frequency_not_timebased(self):
        """Test when policy has sign-in frequency but not time-based - should FAIL."""
        policy_id = str(uuid4())
        display_name = "Test Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
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
                        user_risk_levels=[],
                        device_filter=DeviceFilter(
                            mode=DeviceFilterMode.INCLUDE,
                            rule='device.trustType -ne "ServerAD"',
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[],
                        operator=GrantControlOperator.AND,
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
                )
            }

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_policy_no_all_users(self):
        """Test when policy doesn't target all users - should FAIL."""
        policy_id = str(uuid4())
        display_name = "Test Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
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
                            included_users=["specific-user-id"],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                        device_filter=DeviceFilter(
                            mode=DeviceFilterMode.INCLUDE,
                            rule='device.trustType -ne "ServerAD"',
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[],
                        operator=GrantControlOperator.AND,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=1,
                            type=SignInFrequencyType.HOURS,
                            interval=SignInFrequencyInterval.TIME_BASED,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_policy_no_all_apps(self):
        """Test when policy doesn't target all applications - should FAIL."""
        policy_id = str(uuid4())
        display_name = "Test Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["specific-app-id"],
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
                        device_filter=DeviceFilter(
                            mode=DeviceFilterMode.INCLUDE,
                            rule='device.trustType -ne "ServerAD"',
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[],
                        operator=GrantControlOperator.AND,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=1,
                            type=SignInFrequencyType.HOURS,
                            interval=SignInFrequencyInterval.TIME_BASED,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_policy_no_device_filter(self):
        """Test when policy has no device filter - should FAIL."""
        policy_id = str(uuid4())
        display_name = "Test Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
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
                        user_risk_levels=[],
                        device_filter=None,
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[],
                        operator=GrantControlOperator.AND,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=1,
                            type=SignInFrequencyType.HOURS,
                            interval=SignInFrequencyInterval.TIME_BASED,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_policy_device_filter_wrong_rule(self):
        """Test when policy has device filter but doesn't target non-corporate devices - should FAIL."""
        policy_id = str(uuid4())
        display_name = "Test Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
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
                        user_risk_levels=[],
                        device_filter=DeviceFilter(
                            mode=DeviceFilterMode.INCLUDE,
                            rule="device.displayName -contains 'Windows'",
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[],
                        operator=GrantControlOperator.AND,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=1,
                            type=SignInFrequencyType.HOURS,
                            interval=SignInFrequencyInterval.TIME_BASED,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_policy_compliant_include_non_compliant_devices(self):
        """Test compliant policy using include mode targeting non-compliant devices - should PASS."""
        policy_id = str(uuid4())
        display_name = "Sign-in Frequency Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
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
                        user_risk_levels=[],
                        device_filter=DeviceFilter(
                            mode=DeviceFilterMode.INCLUDE,
                            rule="device.isCompliant -ne True",
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[],
                        operator=GrantControlOperator.AND,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=1,
                            type=SignInFrequencyType.HOURS,
                            interval=SignInFrequencyInterval.TIME_BASED,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_policy_compliant_include_non_hybrid_devices(self):
        """Test compliant policy using include mode targeting non-hybrid AD joined devices - should PASS."""
        policy_id = str(uuid4())
        display_name = "Sign-in Frequency Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
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
                        user_risk_levels=[],
                        device_filter=DeviceFilter(
                            mode=DeviceFilterMode.INCLUDE,
                            rule='device.trustType -ne "ServerAD"',
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[],
                        operator=GrantControlOperator.AND,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=1,
                            type=SignInFrequencyType.HOURS,
                            interval=SignInFrequencyInterval.TIME_BASED,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_policy_compliant_exclude_compliant_devices(self):
        """Test compliant policy using exclude mode excluding compliant devices - should PASS."""
        policy_id = str(uuid4())
        display_name = "Sign-in Frequency Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
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
                        user_risk_levels=[],
                        device_filter=DeviceFilter(
                            mode=DeviceFilterMode.EXCLUDE,
                            rule="device.isCompliant -eq True",
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[],
                        operator=GrantControlOperator.AND,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=1,
                            type=SignInFrequencyType.HOURS,
                            interval=SignInFrequencyInterval.TIME_BASED,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_policy_compliant_exclude_hybrid_devices(self):
        """Test compliant policy using exclude mode excluding hybrid AD joined devices - should PASS."""
        policy_id = str(uuid4())
        display_name = "Sign-in Frequency Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
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
                        user_risk_levels=[],
                        device_filter=DeviceFilter(
                            mode=DeviceFilterMode.EXCLUDE,
                            rule='device.trustType -eq "ServerAD"',
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[],
                        operator=GrantControlOperator.AND,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=1,
                            type=SignInFrequencyType.HOURS,
                            interval=SignInFrequencyInterval.TIME_BASED,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' enforces sign-in frequency for non-corporate devices."
            )

    def test_entra_policy_report_only_mode(self):
        """Test when policy is in report-only mode - should FAIL."""
        policy_id = str(uuid4())
        display_name = "Sign-in Frequency Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_enforce_sign_in_frequency.entra_conditional_access_policy_enforce_sign_in_frequency import (
                entra_conditional_access_policy_enforce_sign_in_frequency,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
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
                        user_risk_levels=[],
                        device_filter=DeviceFilter(
                            mode=DeviceFilterMode.INCLUDE,
                            rule="device.isCompliant -ne True",
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[],
                        operator=GrantControlOperator.AND,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=1,
                            type=SignInFrequencyType.HOURS,
                            interval=SignInFrequencyInterval.TIME_BASED,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                )
            }

            check = entra_conditional_access_policy_enforce_sign_in_frequency()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' is configured to enforce sign-in frequency for non-corporate devices but is in report-only mode."
            )
