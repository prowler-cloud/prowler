from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    ApplicationEnforcedRestrictions,
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


class Test_entra_users_mfa_enabled:
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
                "prowler.providers.m365.services.entra.entra_users_mfa_enabled.entra_users_mfa_enabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_users_mfa_enabled.entra_users_mfa_enabled import (
                entra_users_mfa_enabled,
            )

            entra_client.conditional_access_policies = {}

            check = entra_users_mfa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces MFA for all users."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

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
                "prowler.providers.m365.services.entra.entra_users_mfa_enabled.entra_users_mfa_enabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_users_mfa_enabled.entra_users_mfa_enabled import (
                entra_users_mfa_enabled,
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
                        application_enforced_restrictions=ApplicationEnforcedRestrictions(
                            is_enabled=False
                        ),
                    ),
                    state=ConditionalAccessPolicyState.DISABLED,
                )
            }

            check = entra_users_mfa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces MFA for all users."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_policy_mfa_enabled_for_report(self):
        """
        Valid policy:
         - State enabled for reporting only
         - Applies to administrative roles via 'All' in included_users
         - Application conditions include "All"
         - MFA is configured in grant_controls

         Expected FAIL due to is only for reporting.
        """
        policy_id = str(uuid4())
        display_name = "Invalid MFA Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_users_mfa_enabled.entra_users_mfa_enabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_users_mfa_enabled.entra_users_mfa_enabled import (
                entra_users_mfa_enabled,
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
                        application_enforced_restrictions=ApplicationEnforcedRestrictions(
                            is_enabled=False
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                )
            }

            check = entra_users_mfa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            expected_status_extended = f"Conditional Access Policy '{display_name}' reports MFA requirement for all users but does not enforce it."
            assert result[0].status_extended == expected_status_extended
            assert result[0].resource == entra_client.conditional_access_policies
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id

    def test_policy_valid_through_roles(self):
        """
        Valid policy:
         - State enabled (ENABLED)
         - Applies to administrative roles
         - Application conditions include "All"
         - MFA is configured in grant_controls

         Expected PASS.
        """
        policy_id = str(uuid4())
        display_name = "Valid MFA Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_users_mfa_enabled.entra_users_mfa_enabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_users_mfa_enabled.entra_users_mfa_enabled import (
                entra_users_mfa_enabled,
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
                        application_enforced_restrictions=ApplicationEnforcedRestrictions(
                            is_enabled=False
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_users_mfa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            expected_status_extended = f"Conditional Access Policy '{display_name}' enforces MFA for all users."
            assert result[0].status_extended == expected_status_extended
            assert result[0].resource == entra_client.conditional_access_policies
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
