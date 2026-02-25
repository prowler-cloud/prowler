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
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_entra_emergency_access_exclusion:
    def test_entra_no_conditional_access_policies(self):
        """Test when there are no Conditional Access policies."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_emergency_access_exclusion.entra_emergency_access_exclusion.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_emergency_access_exclusion.entra_emergency_access_exclusion import (
                entra_emergency_access_exclusion,
            )

            entra_client.conditional_access_policies = {}

            check = entra_emergency_access_exclusion()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No enabled Conditional Access policies found. Emergency access exclusions are not required."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_all_policies_disabled(self):
        """Test when all Conditional Access policies are disabled."""
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
                "prowler.providers.m365.services.entra.entra_emergency_access_exclusion.entra_emergency_access_exclusion.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_emergency_access_exclusion.entra_emergency_access_exclusion import (
                entra_emergency_access_exclusion,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
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
                    ),
                    state=ConditionalAccessPolicyState.DISABLED,
                )
            }

            check = entra_emergency_access_exclusion()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No enabled Conditional Access policies found. Emergency access exclusions are not required."
            )

    def test_entra_no_emergency_access_exclusion(self):
        """Test when no user or group is excluded from all policies."""
        policy_id_1 = str(uuid4())
        policy_id_2 = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_emergency_access_exclusion.entra_emergency_access_exclusion.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_emergency_access_exclusion.entra_emergency_access_exclusion import (
                entra_emergency_access_exclusion,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            # Policy 1 excludes user-1, Policy 2 excludes user-2
            # No user is excluded from ALL policies
            entra_client.conditional_access_policies = {
                policy_id_1: ConditionalAccessPolicy(
                    id=policy_id_1,
                    display_name="Policy 1",
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
                            excluded_users=["user-1"],
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
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
                policy_id_2: ConditionalAccessPolicy(
                    id=policy_id_2,
                    display_name="Policy 2",
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
                            excluded_users=["user-2"],
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
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
            }

            check = entra_emergency_access_exclusion()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "No user or group is excluded as emergency access from all 2 enabled Conditional Access policies"
                in result[0].status_extended
            )
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_entra_user_excluded_from_all_policies(self):
        """Test when a user is excluded from all enabled policies."""
        policy_id_1 = str(uuid4())
        policy_id_2 = str(uuid4())
        emergency_user_id = "emergency-access-user"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_emergency_access_exclusion.entra_emergency_access_exclusion.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_emergency_access_exclusion.entra_emergency_access_exclusion import (
                entra_emergency_access_exclusion,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            # Both policies exclude the emergency user
            entra_client.conditional_access_policies = {
                policy_id_1: ConditionalAccessPolicy(
                    id=policy_id_1,
                    display_name="Policy 1",
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
                            excluded_users=[emergency_user_id],
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
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
                policy_id_2: ConditionalAccessPolicy(
                    id=policy_id_2,
                    display_name="Policy 2",
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
                            excluded_users=[emergency_user_id],
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
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
            }

            check = entra_emergency_access_exclusion()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "1 user(s) excluded as emergency access across all 2 enabled Conditional Access policies"
                in result[0].status_extended
            )
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_entra_group_excluded_from_all_policies(self):
        """Test when a group is excluded from all enabled policies."""
        policy_id_1 = str(uuid4())
        policy_id_2 = str(uuid4())
        emergency_group_id = "emergency-access-group"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_emergency_access_exclusion.entra_emergency_access_exclusion.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_emergency_access_exclusion.entra_emergency_access_exclusion import (
                entra_emergency_access_exclusion,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            # Both policies exclude the emergency group
            entra_client.conditional_access_policies = {
                policy_id_1: ConditionalAccessPolicy(
                    id=policy_id_1,
                    display_name="Policy 1",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["All"],
                            excluded_applications=[],
                            included_user_actions=[],
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[emergency_group_id],
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
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
                policy_id_2: ConditionalAccessPolicy(
                    id=policy_id_2,
                    display_name="Policy 2",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["All"],
                            excluded_applications=[],
                            included_user_actions=[],
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[emergency_group_id],
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
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
            }

            check = entra_emergency_access_exclusion()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "1 group(s) excluded as emergency access across all 2 enabled Conditional Access policies"
                in result[0].status_extended
            )
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_entra_user_and_group_excluded_from_all_policies(self):
        """Test when both a user and group are excluded from all enabled policies."""
        policy_id_1 = str(uuid4())
        policy_id_2 = str(uuid4())
        emergency_user_id = "emergency-access-user"
        emergency_group_id = "emergency-access-group"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_emergency_access_exclusion.entra_emergency_access_exclusion.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_emergency_access_exclusion.entra_emergency_access_exclusion import (
                entra_emergency_access_exclusion,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            # Both policies exclude the emergency user and group
            entra_client.conditional_access_policies = {
                policy_id_1: ConditionalAccessPolicy(
                    id=policy_id_1,
                    display_name="Policy 1",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["All"],
                            excluded_applications=[],
                            included_user_actions=[],
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[emergency_group_id],
                            included_users=["All"],
                            excluded_users=[emergency_user_id],
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
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
                policy_id_2: ConditionalAccessPolicy(
                    id=policy_id_2,
                    display_name="Policy 2",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["All"],
                            excluded_applications=[],
                            included_user_actions=[],
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[emergency_group_id],
                            included_users=["All"],
                            excluded_users=[emergency_user_id],
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
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
            }

            check = entra_emergency_access_exclusion()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "1 user(s) and 1 group(s) excluded as emergency access across all 2 enabled Conditional Access policies"
                in result[0].status_extended
            )
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_entra_disabled_policies_ignored(self):
        """Test that disabled policies are ignored when checking exclusions."""
        policy_id_1 = str(uuid4())
        policy_id_2 = str(uuid4())
        emergency_user_id = "emergency-access-user"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_emergency_access_exclusion.entra_emergency_access_exclusion.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_emergency_access_exclusion.entra_emergency_access_exclusion import (
                entra_emergency_access_exclusion,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            # Policy 1 is enabled and excludes user, Policy 2 is disabled (should be ignored)
            entra_client.conditional_access_policies = {
                policy_id_1: ConditionalAccessPolicy(
                    id=policy_id_1,
                    display_name="Enabled Policy",
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
                            excluded_users=[emergency_user_id],
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
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
                policy_id_2: ConditionalAccessPolicy(
                    id=policy_id_2,
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
                            excluded_users=[],  # No exclusions
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
                    ),
                    state=ConditionalAccessPolicyState.DISABLED,
                ),
            }

            check = entra_emergency_access_exclusion()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert (
                "1 user(s) excluded as emergency access across all 1 enabled Conditional Access policies"
                in result[0].status_extended
            )

    def test_entra_enabled_for_reporting_policies_included(self):
        """Test that policies in reporting mode are considered enabled."""
        policy_id_1 = str(uuid4())
        policy_id_2 = str(uuid4())
        emergency_user_id = "emergency-access-user"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_emergency_access_exclusion.entra_emergency_access_exclusion.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_emergency_access_exclusion.entra_emergency_access_exclusion import (
                entra_emergency_access_exclusion,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            # Policy 1 is enabled, Policy 2 is in reporting mode
            # User is excluded from both, so it should PASS
            entra_client.conditional_access_policies = {
                policy_id_1: ConditionalAccessPolicy(
                    id=policy_id_1,
                    display_name="Enabled Policy",
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
                            excluded_users=[emergency_user_id],
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
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
                policy_id_2: ConditionalAccessPolicy(
                    id=policy_id_2,
                    display_name="Reporting Policy",
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
                            excluded_users=[emergency_user_id],
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
                    ),
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                ),
            }

            check = entra_emergency_access_exclusion()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "1 user(s) excluded as emergency access across all 2 enabled Conditional Access policies"
                in result[0].status_extended
            )
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
