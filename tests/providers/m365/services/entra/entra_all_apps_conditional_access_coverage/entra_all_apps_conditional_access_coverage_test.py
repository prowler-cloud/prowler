from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    ApplicationsConditions,
    ConditionalAccessGrantControl,
    ConditionalAccessPolicy,
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


class Test_entra_all_apps_conditional_access_coverage:
    def test_no_conditional_access_policies(self):
        """No conditional access policies configured: expected FAIL."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_all_apps_conditional_access_coverage.entra_all_apps_conditional_access_coverage.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_all_apps_conditional_access_coverage.entra_all_apps_conditional_access_coverage import (
                entra_all_apps_conditional_access_coverage,
            )

            entra_client.conditional_access_policies = {}

            check = entra_all_apps_conditional_access_coverage()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy targets all cloud apps."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_policy_disabled(self):
        """Policy in DISABLED state: expected to be ignored and return FAIL."""
        policy_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_all_apps_conditional_access_coverage.entra_all_apps_conditional_access_coverage.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_all_apps_conditional_access_coverage.entra_all_apps_conditional_access_coverage import (
                entra_all_apps_conditional_access_coverage,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name="Disabled Policy",
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
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
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.DISABLED,
                )
            }

            check = entra_all_apps_conditional_access_coverage()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy targets all cloud apps."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_policy_not_targeting_all_apps(self):
        """Policy does not target all apps: expected FAIL."""
        policy_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_all_apps_conditional_access_coverage.entra_all_apps_conditional_access_coverage.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_all_apps_conditional_access_coverage.entra_all_apps_conditional_access_coverage import (
                entra_all_apps_conditional_access_coverage,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name="Specific Apps Policy",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["app-id-1", "app-id-2"],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
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
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_all_apps_conditional_access_coverage()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy targets all cloud apps."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_policy_with_password_change_requirement(self):
        """Policy with password change requirement: expected to be skipped and return FAIL."""
        policy_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_all_apps_conditional_access_coverage.entra_all_apps_conditional_access_coverage.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_all_apps_conditional_access_coverage.entra_all_apps_conditional_access_coverage import (
                entra_all_apps_conditional_access_coverage,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name="Password Change Policy",
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.PASSWORD_CHANGE
                        ],
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
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_all_apps_conditional_access_coverage()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy targets all cloud apps."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_policy_enabled_for_reporting_only(self):
        """
        Policy targeting all apps but only enabled for reporting:
        expected FAIL with specific message.
        """
        policy_id = str(uuid4())
        display_name = "Reporting Only Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_all_apps_conditional_access_coverage.entra_all_apps_conditional_access_coverage.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_all_apps_conditional_access_coverage.entra_all_apps_conditional_access_coverage import (
                entra_all_apps_conditional_access_coverage,
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
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
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                )
            }

            check = entra_all_apps_conditional_access_coverage()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Conditional Access Policies targeting all cloud apps are only configured for reporting: {display_name}."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_policy_enabled_targeting_all_apps(self):
        """
        Valid policy:
         - State ENABLED
         - Targets all cloud apps
         - No password change requirement

         Expected PASS.
        """
        policy_id = str(uuid4())
        display_name = "All Apps Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_all_apps_conditional_access_coverage.entra_all_apps_conditional_access_coverage.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_all_apps_conditional_access_coverage.entra_all_apps_conditional_access_coverage import (
                entra_all_apps_conditional_access_coverage,
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
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
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_all_apps_conditional_access_coverage()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policies targeting all cloud apps: {display_name}."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_policy_with_block_grant_control(self):
        """
        Valid policy with block grant control:
         - State ENABLED
         - Targets all cloud apps
         - Uses BLOCK grant control

         Expected PASS.
        """
        policy_id = str(uuid4())
        display_name = "Block All Apps Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_all_apps_conditional_access_coverage.entra_all_apps_conditional_access_coverage.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_all_apps_conditional_access_coverage.entra_all_apps_conditional_access_coverage import (
                entra_all_apps_conditional_access_coverage,
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.BLOCK],
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
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_all_apps_conditional_access_coverage()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policies targeting all cloud apps: {display_name}."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_multiple_policies_lists_all_enabled(self):
        """
        Multiple policies:
         - First policy is disabled (skipped)
         - Second policy targets specific apps (skipped)
         - Third and fourth policies are enabled and target all apps

         Expected: single PASS listing both enabled policy names.
        """
        disabled_policy_id = str(uuid4())
        specific_apps_policy_id = str(uuid4())
        policy_a_id = str(uuid4())
        policy_a_name = "MFA All Apps"
        policy_b_id = str(uuid4())
        policy_b_name = "Block All Apps"

        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_all_apps_conditional_access_coverage.entra_all_apps_conditional_access_coverage.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_all_apps_conditional_access_coverage.entra_all_apps_conditional_access_coverage import (
                entra_all_apps_conditional_access_coverage,
            )

            entra_client.conditional_access_policies = {
                disabled_policy_id: ConditionalAccessPolicy(
                    id=disabled_policy_id,
                    display_name="Disabled Policy",
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
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
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.DISABLED,
                ),
                specific_apps_policy_id: ConditionalAccessPolicy(
                    id=specific_apps_policy_id,
                    display_name="Specific Apps Policy",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["app-id-1"],
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
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
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
                policy_a_id: ConditionalAccessPolicy(
                    id=policy_a_id,
                    display_name=policy_a_name,
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
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
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
                policy_b_id: ConditionalAccessPolicy(
                    id=policy_b_id,
                    display_name=policy_b_name,
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.BLOCK],
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
                            interval=SignInFrequencyInterval.EVERY_TIME,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
            }

            check = entra_all_apps_conditional_access_coverage()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert policy_a_name in result[0].status_extended
            assert policy_b_name in result[0].status_extended
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"
