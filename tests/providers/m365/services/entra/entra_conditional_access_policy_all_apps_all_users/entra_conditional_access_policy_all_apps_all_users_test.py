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

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_conditional_access_policy_all_apps_all_users.entra_conditional_access_policy_all_apps_all_users"


def _make_session_controls():
    """Return default session controls for test policies."""
    return SessionControls(
        persistent_browser=PersistentBrowser(is_enabled=False, mode="always"),
        sign_in_frequency=SignInFrequency(
            is_enabled=False,
            frequency=None,
            type=None,
            interval=SignInFrequencyInterval.EVERY_TIME,
        ),
        application_enforced_restrictions=ApplicationEnforcedRestrictions(
            is_enabled=False
        ),
    )


def _make_conditions(
    included_applications=None,
    included_users=None,
    excluded_applications=None,
    excluded_users=None,
    excluded_groups=None,
    excluded_roles=None,
):
    """Return Conditions with the given application and user scopes."""
    return Conditions(
        application_conditions=ApplicationsConditions(
            included_applications=included_applications or ["All"],
            excluded_applications=excluded_applications or [],
            included_user_actions=[],
        ),
        user_conditions=UsersConditions(
            included_groups=[],
            excluded_groups=excluded_groups or [],
            included_users=included_users or ["All"],
            excluded_users=excluded_users or [],
            included_roles=[],
            excluded_roles=excluded_roles or [],
        ),
        client_app_types=[],
        user_risk_levels=[],
    )


def _make_grant_controls(built_in_controls=None):
    """Return GrantControls with the given built-in controls."""
    return GrantControls(
        built_in_controls=built_in_controls or [ConditionalAccessGrantControl.MFA],
        operator=GrantControlOperator.AND,
        authentication_strength=None,
    )


class Test_entra_conditional_access_policy_all_apps_all_users:
    def test_no_conditional_access_policies(self):
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_all_apps_all_users.entra_conditional_access_policy_all_apps_all_users import (
                entra_conditional_access_policy_all_apps_all_users,
            )

            entra_client.conditional_access_policies = {}

            check = entra_conditional_access_policy_all_apps_all_users()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy covers all cloud apps and all users."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_policy_disabled(self):
        policy_id = str(uuid4())
        display_name = "All Apps All Users Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_all_apps_all_users.entra_conditional_access_policy_all_apps_all_users import (
                entra_conditional_access_policy_all_apps_all_users,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=_make_conditions(),
                    grant_controls=_make_grant_controls(),
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.DISABLED,
                )
            }

            check = entra_conditional_access_policy_all_apps_all_users()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy covers all cloud apps and all users."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_policy_excluding_roles(self):
        policy_id = str(uuid4())
        display_name = "All Users Except Role Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_all_apps_all_users.entra_conditional_access_policy_all_apps_all_users import (
                entra_conditional_access_policy_all_apps_all_users,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=_make_conditions(
                        excluded_roles=["62e90394-69f5-4237-9190-012177145e10"],
                    ),
                    grant_controls=_make_grant_controls(),
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_all_apps_all_users()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' targets all cloud apps and all users but includes exclusions. Review excluded users/groups/roles/applications and verify compensating policies protect excluded identities and apps."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[policy_id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
            assert result[0].location == "global"

    def test_policy_not_targeting_all_apps(self):
        policy_id = str(uuid4())
        display_name = "Specific App Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_all_apps_all_users.entra_conditional_access_policy_all_apps_all_users import (
                entra_conditional_access_policy_all_apps_all_users,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=_make_conditions(
                        included_applications=["some-app-id"],
                    ),
                    grant_controls=_make_grant_controls(),
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_all_apps_all_users()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy covers all cloud apps and all users."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_policy_not_targeting_all_users(self):
        policy_id = str(uuid4())
        display_name = "Specific Users Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_all_apps_all_users.entra_conditional_access_policy_all_apps_all_users import (
                entra_conditional_access_policy_all_apps_all_users,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=_make_conditions(
                        included_users=["some-user-id"],
                    ),
                    grant_controls=_make_grant_controls(),
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_all_apps_all_users()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy covers all cloud apps and all users."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_policy_excluding_applications(self):
        policy_id = str(uuid4())
        display_name = "All Apps Except One Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_all_apps_all_users.entra_conditional_access_policy_all_apps_all_users import (
                entra_conditional_access_policy_all_apps_all_users,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=_make_conditions(
                        excluded_applications=["excluded-app-id"],
                    ),
                    grant_controls=_make_grant_controls(),
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_all_apps_all_users()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' targets all cloud apps and all users but includes exclusions. Review excluded users/groups/roles/applications and verify compensating policies protect excluded identities and apps."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[policy_id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
            assert result[0].location == "global"

    def test_policy_excluding_users(self):
        policy_id = str(uuid4())
        display_name = "All Users Except One Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_all_apps_all_users.entra_conditional_access_policy_all_apps_all_users import (
                entra_conditional_access_policy_all_apps_all_users,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=_make_conditions(
                        excluded_users=["excluded-user-id"],
                    ),
                    grant_controls=_make_grant_controls(),
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_all_apps_all_users()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' targets all cloud apps and all users but includes exclusions. Review excluded users/groups/roles/applications and verify compensating policies protect excluded identities and apps."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[policy_id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
            assert result[0].location == "global"

    def test_policy_only_password_change(self):
        policy_id = str(uuid4())
        display_name = "Password Change Only Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_all_apps_all_users.entra_conditional_access_policy_all_apps_all_users import (
                entra_conditional_access_policy_all_apps_all_users,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=_make_conditions(),
                    grant_controls=_make_grant_controls(
                        built_in_controls=[
                            ConditionalAccessGrantControl.PASSWORD_CHANGE
                        ],
                    ),
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_all_apps_all_users()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy covers all cloud apps and all users."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_policy_enabled_for_reporting(self):
        policy_id = str(uuid4())
        display_name = "All Apps All Users - Report Only"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_all_apps_all_users.entra_conditional_access_policy_all_apps_all_users import (
                entra_conditional_access_policy_all_apps_all_users,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=_make_conditions(),
                    grant_controls=_make_grant_controls(),
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                )
            }

            check = entra_conditional_access_policy_all_apps_all_users()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' covers all cloud apps and all users but is only in report-only mode."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[policy_id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
            assert result[0].location == "global"

    def test_policy_enabled_all_apps_all_users(self):
        policy_id = str(uuid4())
        display_name = "All Apps All Users Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_all_apps_all_users.entra_conditional_access_policy_all_apps_all_users import (
                entra_conditional_access_policy_all_apps_all_users,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=_make_conditions(),
                    grant_controls=_make_grant_controls(),
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_all_apps_all_users()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' covers all cloud apps and all users."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[policy_id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
            assert result[0].location == "global"

    def test_multiple_policies_first_disabled_second_enabled(self):
        disabled_id = str(uuid4())
        enabled_id = str(uuid4())
        enabled_name = "All Apps All Users - Enabled"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_all_apps_all_users.entra_conditional_access_policy_all_apps_all_users import (
                entra_conditional_access_policy_all_apps_all_users,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                disabled_id: ConditionalAccessPolicy(
                    id=disabled_id,
                    display_name="All Apps All Users - Disabled",
                    conditions=_make_conditions(),
                    grant_controls=_make_grant_controls(),
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.DISABLED,
                ),
                enabled_id: ConditionalAccessPolicy(
                    id=enabled_id,
                    display_name=enabled_name,
                    conditions=_make_conditions(),
                    grant_controls=_make_grant_controls(),
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
            }

            check = entra_conditional_access_policy_all_apps_all_users()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{enabled_name}' covers all cloud apps and all users."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[enabled_id].dict()
            )
            assert result[0].resource_name == enabled_name
            assert result[0].resource_id == enabled_id
            assert result[0].location == "global"

    def test_policy_with_block_grant_control(self):
        policy_id = str(uuid4())
        display_name = "Block All Apps All Users"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_all_apps_all_users.entra_conditional_access_policy_all_apps_all_users import (
                entra_conditional_access_policy_all_apps_all_users,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=_make_conditions(),
                    grant_controls=_make_grant_controls(
                        built_in_controls=[ConditionalAccessGrantControl.BLOCK],
                    ),
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_all_apps_all_users()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' covers all cloud apps and all users."
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
            assert result[0].location == "global"

    def test_policy_no_application_conditions(self):
        policy_id = str(uuid4())
        display_name = "No App Conditions Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_all_apps_all_users.entra_conditional_access_policy_all_apps_all_users import (
                entra_conditional_access_policy_all_apps_all_users,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name=display_name,
                    conditions=Conditions(
                        application_conditions=None,
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=["All"],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                    ),
                    grant_controls=_make_grant_controls(),
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_all_apps_all_users()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy covers all cloud apps and all users."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_policy_no_user_conditions(self):
        policy_id = str(uuid4())
        display_name = "No User Conditions Policy"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_all_apps_all_users.entra_conditional_access_policy_all_apps_all_users import (
                entra_conditional_access_policy_all_apps_all_users,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
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
                        user_conditions=None,
                        client_app_types=[],
                        user_risk_levels=[],
                    ),
                    grant_controls=_make_grant_controls(),
                    session_controls=_make_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_all_apps_all_users()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy covers all cloud apps and all users."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"
