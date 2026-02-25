from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    ApplicationEnforcedRestrictions,
    ApplicationsConditions,
    ClientAppType,
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


class Test_entra_app_enforced_restrictions:
    def test_entra_no_conditional_access_policies(self):
        """Test FAIL when no conditional access policies exist."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions import (
                entra_app_enforced_restrictions,
            )

            entra_client.conditional_access_policies = {}

            check = entra_app_enforced_restrictions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces application restrictions for unmanaged devices."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_app_enforced_restrictions_policy_disabled(self):
        """Test FAIL when policy with app enforced restrictions is disabled."""
        id = str(uuid4())
        display_name = "App Enforced Restrictions Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions import (
                entra_app_enforced_restrictions,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                id: ConditionalAccessPolicy(
                    id=id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["Office365"],
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
                        client_app_types=[ClientAppType.ALL],
                        user_risk_levels=[],
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
                        application_enforced_restrictions=ApplicationEnforcedRestrictions(
                            is_enabled=True
                        ),
                    ),
                    state=ConditionalAccessPolicyState.DISABLED,
                )
            }

            check = entra_app_enforced_restrictions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces application restrictions for unmanaged devices."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_app_enforced_restrictions_enabled_for_reporting(self):
        """Test FAIL when policy is enabled for reporting but not enforcing."""
        id = str(uuid4())
        display_name = "App Enforced Restrictions Reporting"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions import (
                entra_app_enforced_restrictions,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                id: ConditionalAccessPolicy(
                    id=id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["Office365"],
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
                        client_app_types=[ClientAppType.ALL],
                        user_risk_levels=[],
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
                        application_enforced_restrictions=ApplicationEnforcedRestrictions(
                            is_enabled=True
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                )
            }

            check = entra_app_enforced_restrictions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {display_name} reports application enforced restrictions but does not enforce them."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == id
            assert result[0].location == "global"

    def test_entra_app_enforced_restrictions_not_enabled(self):
        """Test FAIL when policy exists but app enforced restrictions is not enabled."""
        id = str(uuid4())
        display_name = "Policy Without App Restrictions"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions import (
                entra_app_enforced_restrictions,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                id: ConditionalAccessPolicy(
                    id=id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["Office365"],
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
                        client_app_types=[ClientAppType.ALL],
                        user_risk_levels=[],
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
                        application_enforced_restrictions=ApplicationEnforcedRestrictions(
                            is_enabled=False
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_app_enforced_restrictions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces application restrictions for unmanaged devices."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_app_enforced_restrictions_missing_all_users(self):
        """Test FAIL when policy does not include all users."""
        id = str(uuid4())
        display_name = "Policy Missing All Users"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions import (
                entra_app_enforced_restrictions,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                id: ConditionalAccessPolicy(
                    id=id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["Office365"],
                            excluded_applications=[],
                            included_user_actions=[],
                        ),
                        user_conditions=UsersConditions(
                            included_groups=["some-group-id"],
                            excluded_groups=[],
                            included_users=[],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                        client_app_types=[ClientAppType.ALL],
                        user_risk_levels=[],
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
                        application_enforced_restrictions=ApplicationEnforcedRestrictions(
                            is_enabled=True
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_app_enforced_restrictions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces application restrictions for unmanaged devices."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_app_enforced_restrictions_missing_all_client_apps(self):
        """Test FAIL when policy does not include all client app types."""
        id = str(uuid4())
        display_name = "Policy Missing All Client Apps"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions import (
                entra_app_enforced_restrictions,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                id: ConditionalAccessPolicy(
                    id=id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["Office365"],
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
                        client_app_types=[ClientAppType.BROWSER],
                        user_risk_levels=[],
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
                        application_enforced_restrictions=ApplicationEnforcedRestrictions(
                            is_enabled=True
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_app_enforced_restrictions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces application restrictions for unmanaged devices."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_app_enforced_restrictions_missing_required_apps(self):
        """Test FAIL when policy does not include Office365 or the required individual apps."""
        id = str(uuid4())
        display_name = "Policy Missing Required Apps"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions import (
                entra_app_enforced_restrictions,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                id: ConditionalAccessPolicy(
                    id=id,
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
                        client_app_types=[ClientAppType.ALL],
                        user_risk_levels=[],
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
                        application_enforced_restrictions=ApplicationEnforcedRestrictions(
                            is_enabled=True
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_app_enforced_restrictions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces application restrictions for unmanaged devices."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_app_enforced_restrictions_individual_apps_pass(self):
        """Test PASS when policy targets SharePoint and Exchange individually."""
        id = str(uuid4())
        display_name = "Individual Apps Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions import (
                entra_app_enforced_restrictions,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                id: ConditionalAccessPolicy(
                    id=id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[
                                "00000003-0000-0ff1-ce00-000000000000",
                                "00000002-0000-0ff1-ce00-000000000000",
                            ],
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
                        client_app_types=[ClientAppType.ALL],
                        user_risk_levels=[],
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
                        application_enforced_restrictions=ApplicationEnforcedRestrictions(
                            is_enabled=True
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_app_enforced_restrictions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {display_name} enforces application restrictions for unmanaged devices."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == id
            assert result[0].location == "global"

    def test_entra_app_enforced_restrictions_only_sharepoint_fail(self):
        """Test FAIL when policy targets only SharePoint but not Exchange."""
        id = str(uuid4())
        display_name = "Only SharePoint Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions import (
                entra_app_enforced_restrictions,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                id: ConditionalAccessPolicy(
                    id=id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=[
                                "00000003-0000-0ff1-ce00-000000000000",
                            ],
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
                        client_app_types=[ClientAppType.ALL],
                        user_risk_levels=[],
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
                        application_enforced_restrictions=ApplicationEnforcedRestrictions(
                            is_enabled=True
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_app_enforced_restrictions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces application restrictions for unmanaged devices."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_app_enforced_restrictions_browser_and_mobile_pass(self):
        """Test PASS when policy uses browser + mobile apps instead of ALL."""
        id = str(uuid4())
        display_name = "Browser and Mobile Apps Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions import (
                entra_app_enforced_restrictions,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                id: ConditionalAccessPolicy(
                    id=id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["Office365"],
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
                        client_app_types=[
                            ClientAppType.BROWSER,
                            ClientAppType.MOBILE_APPS_AND_DESKTOP_CLIENTS,
                        ],
                        user_risk_levels=[],
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
                        application_enforced_restrictions=ApplicationEnforcedRestrictions(
                            is_enabled=True
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_app_enforced_restrictions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {display_name} enforces application restrictions for unmanaged devices."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == id
            assert result[0].location == "global"

    def test_entra_app_enforced_restrictions_enabled(self):
        """Test PASS when a compliant policy with app enforced restrictions is enabled."""
        id = str(uuid4())
        display_name = "App Enforced Restrictions Enabled"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions import (
                entra_app_enforced_restrictions,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                id: ConditionalAccessPolicy(
                    id=id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["Office365"],
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
                        client_app_types=[ClientAppType.ALL],
                        user_risk_levels=[],
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
                        application_enforced_restrictions=ApplicationEnforcedRestrictions(
                            is_enabled=True
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_app_enforced_restrictions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {display_name} enforces application restrictions for unmanaged devices."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == id
            assert result[0].location == "global"

    def test_entra_app_enforced_restrictions_multiple_policies_one_compliant(self):
        """Test PASS when multiple policies exist and at least one is compliant."""
        id1 = str(uuid4())
        id2 = str(uuid4())
        display_name1 = "Non-Compliant Policy"
        display_name2 = "Compliant App Enforced Restrictions"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_enforced_restrictions.entra_app_enforced_restrictions import (
                entra_app_enforced_restrictions,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                id1: ConditionalAccessPolicy(
                    id=id1,
                    display_name=display_name1,
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
                        client_app_types=[ClientAppType.ALL],
                        user_risk_levels=[],
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
                            interval=SignInFrequencyInterval.TIME_BASED,
                        ),
                        application_enforced_restrictions=ApplicationEnforcedRestrictions(
                            is_enabled=False
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
                id2: ConditionalAccessPolicy(
                    id=id2,
                    display_name=display_name2,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["Office365"],
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
                        client_app_types=[ClientAppType.ALL],
                        user_risk_levels=[],
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
                        application_enforced_restrictions=ApplicationEnforcedRestrictions(
                            is_enabled=True
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
            }

            check = entra_app_enforced_restrictions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {display_name2} enforces application restrictions for unmanaged devices."
            )
            assert result[0].resource_name == display_name2
            assert result[0].resource_id == id2
            assert result[0].location == "global"
