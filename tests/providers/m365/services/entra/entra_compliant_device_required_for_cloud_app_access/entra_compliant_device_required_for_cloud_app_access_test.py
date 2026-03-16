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
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_entra_compliant_device_required_for_cloud_app_access:
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
                "prowler.providers.m365.services.entra.entra_compliant_device_required_for_cloud_app_access.entra_compliant_device_required_for_cloud_app_access.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_compliant_device_required_for_cloud_app_access.entra_compliant_device_required_for_cloud_app_access import (
                entra_compliant_device_required_for_cloud_app_access,
            )

            entra_client.conditional_access_policies = {}

            check = entra_compliant_device_required_for_cloud_app_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires an MDM-compliant device for all cloud app access."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_compliant_device_policy_disabled(self):
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
                "prowler.providers.m365.services.entra.entra_compliant_device_required_for_cloud_app_access.entra_compliant_device_required_for_cloud_app_access.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_compliant_device_required_for_cloud_app_access.entra_compliant_device_required_for_cloud_app_access import (
                entra_compliant_device_required_for_cloud_app_access,
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.COMPLIANT_DEVICE,
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

            check = entra_compliant_device_required_for_cloud_app_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires an MDM-compliant device for all cloud app access."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_compliant_device_enabled_for_reporting(self):
        id = str(uuid4())
        display_name = "Test"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_compliant_device_required_for_cloud_app_access.entra_compliant_device_required_for_cloud_app_access.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_compliant_device_required_for_cloud_app_access.entra_compliant_device_required_for_cloud_app_access import (
                entra_compliant_device_required_for_cloud_app_access,
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.COMPLIANT_DEVICE,
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

            check = entra_compliant_device_required_for_cloud_app_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' reports the requirement of an MDM-compliant device for all cloud app access but does not enforce it."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == id
            assert result[0].location == "global"

    def test_entra_compliant_device_enabled(self):
        id = str(uuid4())
        display_name = "Test"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_compliant_device_required_for_cloud_app_access.entra_compliant_device_required_for_cloud_app_access.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_compliant_device_required_for_cloud_app_access.entra_compliant_device_required_for_cloud_app_access import (
                entra_compliant_device_required_for_cloud_app_access,
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.COMPLIANT_DEVICE,
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

            check = entra_compliant_device_required_for_cloud_app_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' requires an MDM-compliant device for all cloud app access."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == id
            assert result[0].location == "global"

    def test_entra_compliant_device_or_mfa_fails(self):
        id = str(uuid4())
        display_name = "Test"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_compliant_device_required_for_cloud_app_access.entra_compliant_device_required_for_cloud_app_access.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_compliant_device_required_for_cloud_app_access.entra_compliant_device_required_for_cloud_app_access import (
                entra_compliant_device_required_for_cloud_app_access,
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.COMPLIANT_DEVICE,
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

            check = entra_compliant_device_required_for_cloud_app_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires an MDM-compliant device for all cloud app access."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_compliant_device_specific_users_passes(self):
        id = str(uuid4())
        display_name = "Test"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_compliant_device_required_for_cloud_app_access.entra_compliant_device_required_for_cloud_app_access.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_compliant_device_required_for_cloud_app_access.entra_compliant_device_required_for_cloud_app_access import (
                entra_compliant_device_required_for_cloud_app_access,
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
                            included_users=["specific-user-id"],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.COMPLIANT_DEVICE,
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

            check = entra_compliant_device_required_for_cloud_app_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' requires an MDM-compliant device for all cloud app access."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == id
            assert result[0].location == "global"

    def test_entra_compliant_device_not_all_apps_fails(self):
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
                "prowler.providers.m365.services.entra.entra_compliant_device_required_for_cloud_app_access.entra_compliant_device_required_for_cloud_app_access.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_compliant_device_required_for_cloud_app_access.entra_compliant_device_required_for_cloud_app_access import (
                entra_compliant_device_required_for_cloud_app_access,
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.COMPLIANT_DEVICE,
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

            check = entra_compliant_device_required_for_cloud_app_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires an MDM-compliant device for all cloud app access."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_no_compliant_device_control_fails(self):
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
                "prowler.providers.m365.services.entra.entra_compliant_device_required_for_cloud_app_access.entra_compliant_device_required_for_cloud_app_access.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_compliant_device_required_for_cloud_app_access.entra_compliant_device_required_for_cloud_app_access import (
                entra_compliant_device_required_for_cloud_app_access,
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

            check = entra_compliant_device_required_for_cloud_app_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires an MDM-compliant device for all cloud app access."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_compliant_device_and_mfa_passes(self):
        id = str(uuid4())
        display_name = "Test"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_compliant_device_required_for_cloud_app_access.entra_compliant_device_required_for_cloud_app_access.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_compliant_device_required_for_cloud_app_access.entra_compliant_device_required_for_cloud_app_access import (
                entra_compliant_device_required_for_cloud_app_access,
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.COMPLIANT_DEVICE,
                            ConditionalAccessGrantControl.MFA,
                        ],
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
                            interval=SignInFrequencyInterval.TIME_BASED,
                        ),
                        application_enforced_restrictions=ApplicationEnforcedRestrictions(
                            is_enabled=False
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_compliant_device_required_for_cloud_app_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' requires an MDM-compliant device for all cloud app access."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == id
            assert result[0].location == "global"
