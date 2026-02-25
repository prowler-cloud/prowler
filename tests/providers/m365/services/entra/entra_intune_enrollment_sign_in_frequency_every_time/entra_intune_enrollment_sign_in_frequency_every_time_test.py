from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    ApplicationEnforcedRestrictions,
    ApplicationsConditions,
    ConditionalAccessPolicyState,
    Conditions,
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


class Test_entra_intune_enrollment_sign_in_frequency_every_time:
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
                "prowler.providers.m365.services.entra.entra_intune_enrollment_sign_in_frequency_every_time.entra_intune_enrollment_sign_in_frequency_every_time.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_intune_enrollment_sign_in_frequency_every_time.entra_intune_enrollment_sign_in_frequency_every_time import (
                entra_intune_enrollment_sign_in_frequency_every_time,
            )

            entra_client.conditional_access_policies = {}

            check = entra_intune_enrollment_sign_in_frequency_every_time()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces Every Time sign-in frequency for Intune Enrollment."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_intune_enrollment_sign_in_frequency_every_time_disabled(self):
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
                "prowler.providers.m365.services.entra.entra_intune_enrollment_sign_in_frequency_every_time.entra_intune_enrollment_sign_in_frequency_every_time.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_intune_enrollment_sign_in_frequency_every_time.entra_intune_enrollment_sign_in_frequency_every_time import (
                entra_intune_enrollment_sign_in_frequency_every_time,
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
                            included_applications=[
                                "d4ebce55-015a-49b5-a083-c84d1797ae8c"
                            ],  # Intune Enrollment
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
                        built_in_controls=[], operator=GrantControlOperator.AND
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

            check = entra_intune_enrollment_sign_in_frequency_every_time()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces Every Time sign-in frequency for Intune Enrollment."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_intune_sign_in_frequency_every_time_enabled(self):
        id = str(uuid4())
        display_name = "Test Intune Enrollment Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_intune_enrollment_sign_in_frequency_every_time.entra_intune_enrollment_sign_in_frequency_every_time.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_intune_enrollment_sign_in_frequency_every_time.entra_intune_enrollment_sign_in_frequency_every_time import (
                entra_intune_enrollment_sign_in_frequency_every_time,
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
                                "0000000a-0000-0000-c000-000000000000"
                            ],  # Intune Enrollment
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
                        built_in_controls=[], operator=GrantControlOperator.AND
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=True, mode="never"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
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

            check = entra_intune_enrollment_sign_in_frequency_every_time()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces Every Time sign-in frequency for Intune Enrollment."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_all_users_intune_enrollment_4hours(self):
        id = str(uuid4())
        display_name = "Test All Users Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_intune_enrollment_sign_in_frequency_every_time.entra_intune_enrollment_sign_in_frequency_every_time.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_intune_enrollment_sign_in_frequency_every_time.entra_intune_enrollment_sign_in_frequency_every_time import (
                entra_intune_enrollment_sign_in_frequency_every_time,
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
                        built_in_controls=[], operator=GrantControlOperator.AND
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=True, mode="never"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
                            frequency=4,
                            type=SignInFrequencyType.HOURS,
                            interval=SignInFrequencyInterval.TIME_BASED,
                        ),
                        application_enforced_restrictions=ApplicationEnforcedRestrictions(
                            is_enabled=False
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_intune_enrollment_sign_in_frequency_every_time()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces Every Time sign-in frequency for Intune Enrollment."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_intune_enrollment_enabled_for_reporting(self):
        id = str(uuid4())
        display_name = "Test Report-Only Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_intune_enrollment_sign_in_frequency_every_time.entra_intune_enrollment_sign_in_frequency_every_time.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_intune_enrollment_sign_in_frequency_every_time.entra_intune_enrollment_sign_in_frequency_every_time import (
                entra_intune_enrollment_sign_in_frequency_every_time,
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
                                "d4ebce55-015a-49b5-a083-c84d1797ae8c"
                            ],  # Intune Enrollment
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
                        built_in_controls=[], operator=GrantControlOperator.AND
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=True, mode="never"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=True,
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

            check = entra_intune_enrollment_sign_in_frequency_every_time()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {display_name} reports Every Time sign-in frequency for Intune Enrollment but does not enforce it."
            )
            assert result[0].resource == entra_client.conditional_access_policies[id]
            assert result[0].resource_name == display_name
            assert result[0].resource_id == id
            assert result[0].location == "global"
