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


class Test_entra_managed_device_required_for_authentication:
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
                "prowler.providers.m365.services.entra.entra_managed_device_required_for_authentication.entra_managed_device_required_for_authentication.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_managed_device_required_for_authentication.entra_managed_device_required_for_authentication import (
                entra_managed_device_required_for_authentication,
            )

            entra_client.conditional_access_policies = {}

            check = entra_managed_device_required_for_authentication()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires a managed device for authentication."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_managed_device_disabled(self):
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
                "prowler.providers.m365.services.entra.entra_managed_device_required_for_authentication.entra_managed_device_required_for_authentication.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_managed_device_required_for_authentication.entra_managed_device_required_for_authentication import (
                entra_managed_device_required_for_authentication,
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
                            included_applications=[],
                            excluded_applications=[],
                            included_user_actions=[],
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=[],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[], operator=GrantControlOperator.OR
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
                        application_enforced_restrictions=ApplicationEnforcedRestrictions(is_enabled=False),
                    ),
                    state=ConditionalAccessPolicyState.DISABLED,
                )
            }

            check = entra_managed_device_required_for_authentication()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires a managed device for authentication."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_managed_device_enabled_for_reporting(self):
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
                "prowler.providers.m365.services.entra.entra_managed_device_required_for_authentication.entra_managed_device_required_for_authentication.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_managed_device_required_for_authentication.entra_managed_device_required_for_authentication import (
                entra_managed_device_required_for_authentication,
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
                            ConditionalAccessGrantControl.MFA,
                            ConditionalAccessGrantControl.DOMAIN_JOINED_DEVICE,
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
                        application_enforced_restrictions=ApplicationEnforcedRestrictions(is_enabled=False),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                )
            }

            check = entra_managed_device_required_for_authentication()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' reports the requirement of a managed device for authentication but does not enforce it."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[id].dict()
            )

            assert result[0].resource_name == display_name
            assert result[0].resource_id == id
            assert result[0].location == "global"

    def test_entra_managed_device_enabled(self):
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
                "prowler.providers.m365.services.entra.entra_managed_device_required_for_authentication.entra_managed_device_required_for_authentication.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_managed_device_required_for_authentication.entra_managed_device_required_for_authentication import (
                entra_managed_device_required_for_authentication,
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
                            ConditionalAccessGrantControl.MFA,
                            ConditionalAccessGrantControl.DOMAIN_JOINED_DEVICE,
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
                        application_enforced_restrictions=ApplicationEnforcedRestrictions(is_enabled=False),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_managed_device_required_for_authentication()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' does require a managed device for authentication."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[id].dict()
            )

            assert result[0].resource_name == display_name
            assert result[0].resource_id == id
            assert result[0].location == "global"
