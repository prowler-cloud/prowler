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

CHECK_MODULE = "prowler.providers.m365.services.entra.entra_policy_requires_compliant_device_or_mfa.entra_policy_requires_compliant_device_or_mfa"

DEFAULT_SESSION_CONTROLS = SessionControls(
    persistent_browser=PersistentBrowser(is_enabled=False, mode="always"),
    sign_in_frequency=SignInFrequency(
        is_enabled=False,
        frequency=None,
        type=None,
        interval=SignInFrequencyInterval.TIME_BASED,
    ),
    application_enforced_restrictions=ApplicationEnforcedRestrictions(is_enabled=False),
)

EMPTY_USER_CONDITIONS = UsersConditions(
    included_groups=[],
    excluded_groups=[],
    included_users=[],
    excluded_users=[],
    included_roles=[],
    excluded_roles=[],
)

ALL_USER_CONDITIONS = UsersConditions(
    included_groups=[],
    excluded_groups=[],
    included_users=["All"],
    excluded_users=[],
    included_roles=[],
    excluded_roles=[],
)

EMPTY_APP_CONDITIONS = ApplicationsConditions(
    included_applications=[],
    excluded_applications=[],
    included_user_actions=[],
)

ALL_APP_CONDITIONS = ApplicationsConditions(
    included_applications=["All"],
    excluded_applications=[],
    included_user_actions=[],
)

COMPLIANT_GRANT_CONTROLS = GrantControls(
    built_in_controls=[
        ConditionalAccessGrantControl.MFA,
        ConditionalAccessGrantControl.COMPLIANT_DEVICE,
        ConditionalAccessGrantControl.DOMAIN_JOINED_DEVICE,
    ],
    operator=GrantControlOperator.OR,
)


class Test_entra_policy_requires_compliant_device_or_mfa:
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
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_requires_compliant_device_or_mfa.entra_policy_requires_compliant_device_or_mfa import (
                entra_policy_requires_compliant_device_or_mfa,
            )

            entra_client.conditional_access_policies = {}

            check = entra_policy_requires_compliant_device_or_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires compliant device, hybrid join, or MFA as alternative grant controls for all users."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_entra_policy_disabled(self):
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
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_requires_compliant_device_or_mfa.entra_policy_requires_compliant_device_or_mfa import (
                entra_policy_requires_compliant_device_or_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name="Disabled Policy",
                    conditions=Conditions(
                        application_conditions=ALL_APP_CONDITIONS,
                        user_conditions=ALL_USER_CONDITIONS,
                        client_app_types=[
                            ClientAppType.BROWSER,
                            ClientAppType.MOBILE_APPS_AND_DESKTOP_CLIENTS,
                        ],
                    ),
                    grant_controls=COMPLIANT_GRANT_CONTROLS,
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.DISABLED,
                )
            }

            check = entra_policy_requires_compliant_device_or_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires compliant device, hybrid join, or MFA as alternative grant controls for all users."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_entra_policy_not_targeting_all_users(self):
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
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_requires_compliant_device_or_mfa.entra_policy_requires_compliant_device_or_mfa import (
                entra_policy_requires_compliant_device_or_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name="Not All Users",
                    conditions=Conditions(
                        application_conditions=ALL_APP_CONDITIONS,
                        user_conditions=EMPTY_USER_CONDITIONS,
                        client_app_types=[
                            ClientAppType.BROWSER,
                            ClientAppType.MOBILE_APPS_AND_DESKTOP_CLIENTS,
                        ],
                    ),
                    grant_controls=COMPLIANT_GRANT_CONTROLS,
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_policy_requires_compliant_device_or_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires compliant device, hybrid join, or MFA as alternative grant controls for all users."
            )

    def test_entra_policy_not_targeting_all_apps(self):
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
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_requires_compliant_device_or_mfa.entra_policy_requires_compliant_device_or_mfa import (
                entra_policy_requires_compliant_device_or_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name="Not All Apps",
                    conditions=Conditions(
                        application_conditions=EMPTY_APP_CONDITIONS,
                        user_conditions=ALL_USER_CONDITIONS,
                        client_app_types=[
                            ClientAppType.BROWSER,
                            ClientAppType.MOBILE_APPS_AND_DESKTOP_CLIENTS,
                        ],
                    ),
                    grant_controls=COMPLIANT_GRANT_CONTROLS,
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_policy_requires_compliant_device_or_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires compliant device, hybrid join, or MFA as alternative grant controls for all users."
            )

    def test_entra_policy_missing_client_app_types(self):
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
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_requires_compliant_device_or_mfa.entra_policy_requires_compliant_device_or_mfa import (
                entra_policy_requires_compliant_device_or_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name="Missing Client App Types",
                    conditions=Conditions(
                        application_conditions=ALL_APP_CONDITIONS,
                        user_conditions=ALL_USER_CONDITIONS,
                        client_app_types=[ClientAppType.BROWSER],
                    ),
                    grant_controls=COMPLIANT_GRANT_CONTROLS,
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_policy_requires_compliant_device_or_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires compliant device, hybrid join, or MFA as alternative grant controls for all users."
            )

    def test_entra_policy_missing_grant_controls(self):
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
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_requires_compliant_device_or_mfa.entra_policy_requires_compliant_device_or_mfa import (
                entra_policy_requires_compliant_device_or_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name="Missing Grant Controls",
                    conditions=Conditions(
                        application_conditions=ALL_APP_CONDITIONS,
                        user_conditions=ALL_USER_CONDITIONS,
                        client_app_types=[
                            ClientAppType.BROWSER,
                            ClientAppType.MOBILE_APPS_AND_DESKTOP_CLIENTS,
                        ],
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                    ),
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_policy_requires_compliant_device_or_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires compliant device, hybrid join, or MFA as alternative grant controls for all users."
            )

    def test_entra_policy_and_operator(self):
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
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_requires_compliant_device_or_mfa.entra_policy_requires_compliant_device_or_mfa import (
                entra_policy_requires_compliant_device_or_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name="AND Operator Policy",
                    conditions=Conditions(
                        application_conditions=ALL_APP_CONDITIONS,
                        user_conditions=ALL_USER_CONDITIONS,
                        client_app_types=[
                            ClientAppType.BROWSER,
                            ClientAppType.MOBILE_APPS_AND_DESKTOP_CLIENTS,
                        ],
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.MFA,
                            ConditionalAccessGrantControl.COMPLIANT_DEVICE,
                            ConditionalAccessGrantControl.DOMAIN_JOINED_DEVICE,
                        ],
                        operator=GrantControlOperator.AND,
                    ),
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_policy_requires_compliant_device_or_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires compliant device, hybrid join, or MFA as alternative grant controls for all users."
            )

    def test_entra_policy_enabled_for_reporting(self):
        policy_id = str(uuid4())
        display_name = "Report Only Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_requires_compliant_device_or_mfa.entra_policy_requires_compliant_device_or_mfa import (
                entra_policy_requires_compliant_device_or_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ALL_APP_CONDITIONS,
                        user_conditions=ALL_USER_CONDITIONS,
                        client_app_types=[
                            ClientAppType.BROWSER,
                            ClientAppType.MOBILE_APPS_AND_DESKTOP_CLIENTS,
                        ],
                    ),
                    grant_controls=COMPLIANT_GRANT_CONTROLS,
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                )
            }

            check = entra_policy_requires_compliant_device_or_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' reports the requirement of compliant device, hybrid join, or MFA for all users but does not enforce it."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[policy_id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
            assert result[0].location == "global"

    def test_entra_policy_enabled_pass(self):
        policy_id = str(uuid4())
        display_name = "Compliant Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_requires_compliant_device_or_mfa.entra_policy_requires_compliant_device_or_mfa import (
                entra_policy_requires_compliant_device_or_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ALL_APP_CONDITIONS,
                        user_conditions=ALL_USER_CONDITIONS,
                        client_app_types=[
                            ClientAppType.BROWSER,
                            ClientAppType.MOBILE_APPS_AND_DESKTOP_CLIENTS,
                        ],
                    ),
                    grant_controls=COMPLIANT_GRANT_CONTROLS,
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_policy_requires_compliant_device_or_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' requires compliant device, hybrid join, or MFA for all users."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[policy_id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
            assert result[0].location == "global"

    def test_entra_policy_enabled_with_client_app_type_all(self):
        policy_id = str(uuid4())
        display_name = "All Client Apps Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_requires_compliant_device_or_mfa.entra_policy_requires_compliant_device_or_mfa import (
                entra_policy_requires_compliant_device_or_mfa,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=ALL_APP_CONDITIONS,
                        user_conditions=ALL_USER_CONDITIONS,
                        client_app_types=[ClientAppType.ALL],
                    ),
                    grant_controls=COMPLIANT_GRANT_CONTROLS,
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_policy_requires_compliant_device_or_mfa()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' requires compliant device, hybrid join, or MFA for all users."
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
