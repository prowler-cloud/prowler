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
    PlatformConditions,
    SessionControls,
    SignInFrequency,
    SignInFrequencyInterval,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_entra_conditional_access_policy_approved_client_app_required_for_mobile:
    def test_entra_no_conditional_access_policies(self):
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile import (
                entra_conditional_access_policy_approved_client_app_required_for_mobile,
            )

            entra_client.conditional_access_policies = {}

            check = (
                entra_conditional_access_policy_approved_client_app_required_for_mobile()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires approved client apps or app protection for mobile devices."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_policy_disabled(self):
        id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile import (
                entra_conditional_access_policy_approved_client_app_required_for_mobile,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                id: ConditionalAccessPolicy(
                    id=id,
                    display_name="Test",
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
                        platform_conditions=PlatformConditions(
                            include_platforms=["android", "iOS"],
                            exclude_platforms=[],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.APPROVED_APPLICATION,
                            ConditionalAccessGrantControl.COMPLIANT_APPLICATION,
                        ],
                        operator=GrantControlOperator.OR,
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
                    state=ConditionalAccessPolicyState.DISABLED,
                )
            }

            check = (
                entra_conditional_access_policy_approved_client_app_required_for_mobile()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires approved client apps or app protection for mobile devices."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_policy_enabled_for_reporting(self):
        id = str(uuid4())
        display_name = "Require Approved Apps for Mobile"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile import (
                entra_conditional_access_policy_approved_client_app_required_for_mobile,
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
                        platform_conditions=PlatformConditions(
                            include_platforms=["android", "iOS"],
                            exclude_platforms=[],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.APPROVED_APPLICATION,
                            ConditionalAccessGrantControl.COMPLIANT_APPLICATION,
                        ],
                        operator=GrantControlOperator.OR,
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
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                )
            }

            check = (
                entra_conditional_access_policy_approved_client_app_required_for_mobile()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {display_name} reports the requirement of approved client apps or app protection for mobile devices but does not enforce it."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == id
            assert result[0].location == "global"

    def test_entra_policy_enabled(self):
        id = str(uuid4())
        display_name = "Require Approved Apps for Mobile"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile import (
                entra_conditional_access_policy_approved_client_app_required_for_mobile,
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
                        platform_conditions=PlatformConditions(
                            include_platforms=["android", "iOS"],
                            exclude_platforms=[],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.APPROVED_APPLICATION,
                            ConditionalAccessGrantControl.COMPLIANT_APPLICATION,
                        ],
                        operator=GrantControlOperator.OR,
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

            check = (
                entra_conditional_access_policy_approved_client_app_required_for_mobile()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {display_name} requires approved client apps or app protection for mobile devices."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == id
            assert result[0].location == "global"

    def test_entra_policy_missing_platform(self):
        id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile import (
                entra_conditional_access_policy_approved_client_app_required_for_mobile,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                id: ConditionalAccessPolicy(
                    id=id,
                    display_name="Test",
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
                        platform_conditions=PlatformConditions(
                            include_platforms=["android"],
                            exclude_platforms=[],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.APPROVED_APPLICATION,
                        ],
                        operator=GrantControlOperator.OR,
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

            check = (
                entra_conditional_access_policy_approved_client_app_required_for_mobile()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires approved client apps or app protection for mobile devices."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_policy_missing_grant_controls(self):
        id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile import (
                entra_conditional_access_policy_approved_client_app_required_for_mobile,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                id: ConditionalAccessPolicy(
                    id=id,
                    display_name="Test",
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
                        platform_conditions=PlatformConditions(
                            include_platforms=["android", "iOS"],
                            exclude_platforms=[],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.MFA,
                        ],
                        operator=GrantControlOperator.OR,
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

            check = (
                entra_conditional_access_policy_approved_client_app_required_for_mobile()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires approved client apps or app protection for mobile devices."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_policy_no_platform_conditions(self):
        id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile import (
                entra_conditional_access_policy_approved_client_app_required_for_mobile,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                id: ConditionalAccessPolicy(
                    id=id,
                    display_name="Test",
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
                        platform_conditions=None,
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.APPROVED_APPLICATION,
                        ],
                        operator=GrantControlOperator.OR,
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

            check = (
                entra_conditional_access_policy_approved_client_app_required_for_mobile()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires approved client apps or app protection for mobile devices."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_policy_missing_ios_platform(self):
        id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile import (
                entra_conditional_access_policy_approved_client_app_required_for_mobile,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                id: ConditionalAccessPolicy(
                    id=id,
                    display_name="Test",
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
                        platform_conditions=PlatformConditions(
                            include_platforms=["iOS"],
                            exclude_platforms=[],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.APPROVED_APPLICATION,
                        ],
                        operator=GrantControlOperator.OR,
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

            check = (
                entra_conditional_access_policy_approved_client_app_required_for_mobile()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires approved client apps or app protection for mobile devices."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_policy_only_approved_app(self):
        id = str(uuid4())
        display_name = "Require Approved Client App for Mobile"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile import (
                entra_conditional_access_policy_approved_client_app_required_for_mobile,
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
                        platform_conditions=PlatformConditions(
                            include_platforms=["android", "iOS"],
                            exclude_platforms=[],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.APPROVED_APPLICATION,
                        ],
                        operator=GrantControlOperator.OR,
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

            check = (
                entra_conditional_access_policy_approved_client_app_required_for_mobile()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {display_name} requires approved client apps or app protection for mobile devices."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == id
            assert result[0].location == "global"

    def test_entra_policy_only_compliant_app(self):
        id = str(uuid4())
        display_name = "Require App Protection for Mobile"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile import (
                entra_conditional_access_policy_approved_client_app_required_for_mobile,
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
                        platform_conditions=PlatformConditions(
                            include_platforms=["android", "iOS"],
                            exclude_platforms=[],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.COMPLIANT_APPLICATION,
                        ],
                        operator=GrantControlOperator.OR,
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

            check = (
                entra_conditional_access_policy_approved_client_app_required_for_mobile()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {display_name} requires approved client apps or app protection for mobile devices."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == id
            assert result[0].location == "global"

    def test_entra_report_only_policy_then_enabled_policy(self):
        report_id = str(uuid4())
        enabled_id = str(uuid4())
        report_name = "Report Only Policy"
        enabled_name = "Enforced Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile import (
                entra_conditional_access_policy_approved_client_app_required_for_mobile,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                report_id: ConditionalAccessPolicy(
                    id=report_id,
                    display_name=report_name,
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
                        platform_conditions=PlatformConditions(
                            include_platforms=["android", "iOS"],
                            exclude_platforms=[],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.APPROVED_APPLICATION,
                            ConditionalAccessGrantControl.COMPLIANT_APPLICATION,
                        ],
                        operator=GrantControlOperator.OR,
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
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                ),
                enabled_id: ConditionalAccessPolicy(
                    id=enabled_id,
                    display_name=enabled_name,
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
                        platform_conditions=PlatformConditions(
                            include_platforms=["android", "iOS"],
                            exclude_platforms=[],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.COMPLIANT_APPLICATION,
                        ],
                        operator=GrantControlOperator.OR,
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
            }

            check = (
                entra_conditional_access_policy_approved_client_app_required_for_mobile()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {enabled_name} requires approved client apps or app protection for mobile devices."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[enabled_id].dict()
            )
            assert result[0].resource_name == enabled_name
            assert result[0].resource_id == enabled_id
            assert result[0].location == "global"

    def test_entra_policy_all_platforms_enabled(self):
        id = str(uuid4())
        display_name = "Require App Protection for All Platforms"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile import (
                entra_conditional_access_policy_approved_client_app_required_for_mobile,
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
                        platform_conditions=PlatformConditions(
                            include_platforms=["all"],
                            exclude_platforms=[],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.COMPLIANT_APPLICATION,
                        ],
                        operator=GrantControlOperator.OR,
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

            check = (
                entra_conditional_access_policy_approved_client_app_required_for_mobile()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {display_name} requires approved client apps or app protection for mobile devices."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == id
            assert result[0].location == "global"

    def test_entra_policy_excludes_ios_platform(self):
        id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile import (
                entra_conditional_access_policy_approved_client_app_required_for_mobile,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                id: ConditionalAccessPolicy(
                    id=id,
                    display_name="Exclude iOS",
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
                        platform_conditions=PlatformConditions(
                            include_platforms=["all"],
                            exclude_platforms=["iOS"],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.COMPLIANT_APPLICATION,
                        ],
                        operator=GrantControlOperator.OR,
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

            check = (
                entra_conditional_access_policy_approved_client_app_required_for_mobile()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires approved client apps or app protection for mobile devices."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_policy_or_operator_with_extra_control(self):
        id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_approved_client_app_required_for_mobile.entra_conditional_access_policy_approved_client_app_required_for_mobile import (
                entra_conditional_access_policy_approved_client_app_required_for_mobile,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                id: ConditionalAccessPolicy(
                    id=id,
                    display_name="App Protection Or MFA",
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
                        platform_conditions=PlatformConditions(
                            include_platforms=["android", "iOS"],
                            exclude_platforms=[],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.COMPLIANT_APPLICATION,
                            ConditionalAccessGrantControl.MFA,
                        ],
                        operator=GrantControlOperator.OR,
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

            check = (
                entra_conditional_access_policy_approved_client_app_required_for_mobile()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires approved client apps or app protection for mobile devices."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"
