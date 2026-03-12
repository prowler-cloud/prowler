from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    AdminRoles,
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

CHECK_MODULE = "prowler.providers.m365.services.entra.entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required.entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required"

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

ADMIN_ROLE_USER_CONDITIONS = UsersConditions(
    included_groups=[],
    excluded_groups=[],
    included_users=[],
    excluded_users=[],
    included_roles=[AdminRoles.GLOBAL_ADMINISTRATOR.value],
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

REQUIRED_GRANT_CONTROLS = GrantControls(
    built_in_controls=[
        ConditionalAccessGrantControl.MFA,
        ConditionalAccessGrantControl.COMPLIANT_DEVICE,
        ConditionalAccessGrantControl.DOMAIN_JOINED_DEVICE,
    ],
    operator=GrantControlOperator.OR,
)


class Test_entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required:
    def test_entra_no_conditional_access_policies(self):
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required.entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required import (
                entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required,
            )

            entra_client.conditional_access_policies = {}
            result = (
                entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required()
            ).execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires compliant device, hybrid joined device, or MFA for admin roles or all users across all cloud apps."
            )

    def test_entra_policy_not_targeting_admins_or_all_users(self):
        policy_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required.entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required import (
                entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name="No Admins or All Users",
                    conditions=Conditions(
                        application_conditions=ALL_APP_CONDITIONS,
                        user_conditions=EMPTY_USER_CONDITIONS,
                        client_app_types=[],
                    ),
                    grant_controls=REQUIRED_GRANT_CONTROLS,
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            result = (
                entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required()
            ).execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

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
            mock.patch(f"{CHECK_MODULE}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required.entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required import (
                entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required,
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
                        client_app_types=[],
                    ),
                    grant_controls=REQUIRED_GRANT_CONTROLS,
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            result = (
                entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required()
            ).execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_entra_policy_missing_required_controls(self):
        policy_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required.entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required import (
                entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name="Missing Hybrid Joined",
                    conditions=Conditions(
                        application_conditions=ALL_APP_CONDITIONS,
                        user_conditions=ALL_USER_CONDITIONS,
                        client_app_types=[],
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.MFA,
                            ConditionalAccessGrantControl.COMPLIANT_DEVICE,
                        ],
                        operator=GrantControlOperator.OR,
                    ),
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            result = (
                entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required()
            ).execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_entra_policy_operator_not_or(self):
        policy_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required.entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required import (
                entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name="AND Operator",
                    conditions=Conditions(
                        application_conditions=ALL_APP_CONDITIONS,
                        user_conditions=ALL_USER_CONDITIONS,
                        client_app_types=[],
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

            result = (
                entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required()
            ).execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_entra_policy_reporting_only(self):
        policy_id = str(uuid4())
        display_name = "Report Only"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required.entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required import (
                entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required,
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
                        user_conditions=ADMIN_ROLE_USER_CONDITIONS,
                        client_app_types=[],
                    ),
                    grant_controls=REQUIRED_GRANT_CONTROLS,
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                )
            }

            result = (
                entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required()
            ).execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {display_name} reports compliant device, hybrid joined device, or MFA for admin roles or all users but does not enforce it."
            )

    def test_entra_policy_enabled_pass_for_all_users(self):
        policy_id = str(uuid4())
        display_name = "All Users"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required.entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required import (
                entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required,
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
                        client_app_types=[],
                    ),
                    grant_controls=REQUIRED_GRANT_CONTROLS,
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            result = (
                entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required()
            ).execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {display_name} enforces compliant device, hybrid joined device, or MFA for admin roles or all users across all cloud apps."
            )

    def test_entra_policy_enabled_pass_for_admin_roles(self):
        policy_id = str(uuid4())
        display_name = "Admin Roles"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required.entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required import (
                entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required,
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
                        user_conditions=ADMIN_ROLE_USER_CONDITIONS,
                        client_app_types=[],
                    ),
                    grant_controls=REQUIRED_GRANT_CONTROLS,
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            result = (
                entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required()
            ).execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
