"""Tests for the entra_conditional_access_policy_references_deleted_principals check."""

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
    Group,
    PersistentBrowser,
    SessionControls,
    SignInFrequency,
    SignInFrequencyInterval,
    User,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_conditional_access_policy_references_deleted_principals.entra_conditional_access_policy_references_deleted_principals"


def _default_session_controls():
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


def _default_grant_controls():
    return GrantControls(
        built_in_controls=[ConditionalAccessGrantControl.MFA],
        operator=GrantControlOperator.AND,
        authentication_strength=None,
    )


class Test_entra_conditional_access_policy_references_deleted_principals:
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_references_deleted_principals.entra_conditional_access_policy_references_deleted_principals import (
                entra_conditional_access_policy_references_deleted_principals,
            )

            entra_client.conditional_access_policies = {}
            entra_client.users = {}
            entra_client.groups = []

            check = entra_conditional_access_policy_references_deleted_principals()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No enabled Conditional Access Policies found to evaluate."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_policy_disabled(self):
        policy_id = str(uuid4())
        display_name = "Disabled Policy"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_references_deleted_principals.entra_conditional_access_policy_references_deleted_principals import (
                entra_conditional_access_policy_references_deleted_principals,
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
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=["deleted-user-id"],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                    ),
                    grant_controls=_default_grant_controls(),
                    session_controls=_default_session_controls(),
                    state=ConditionalAccessPolicyState.DISABLED,
                )
            }
            entra_client.users = {}
            entra_client.groups = []

            check = entra_conditional_access_policy_references_deleted_principals()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No enabled Conditional Access Policies found to evaluate."
            )

    def test_policy_with_valid_users_and_groups(self):
        user_id = str(uuid4())
        group_id = str(uuid4())
        policy_id = str(uuid4())
        display_name = "MFA for All"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_references_deleted_principals.entra_conditional_access_policy_references_deleted_principals import (
                entra_conditional_access_policy_references_deleted_principals,
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
                        user_conditions=UsersConditions(
                            included_groups=[group_id],
                            excluded_groups=[],
                            included_users=[user_id],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                    ),
                    grant_controls=_default_grant_controls(),
                    session_controls=_default_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }
            entra_client.users = {
                user_id: User(
                    id=user_id,
                    name="Test User",
                    on_premises_sync_enabled=False,
                    directory_roles_ids=[],
                    is_mfa_capable=True,
                    account_enabled=True,
                    authentication_methods=["password"],
                    user_type="Member",
                )
            }
            entra_client.groups = [
                Group(id=group_id, name="Test Group", groupTypes=[], membershipRule=None)
            ]

            check = entra_conditional_access_policy_references_deleted_principals()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {display_name} does not reference any deleted users, groups, or roles."
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id

    def test_policy_references_deleted_user(self):
        deleted_user_id = str(uuid4())
        policy_id = str(uuid4())
        display_name = "Block Deleted User"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_references_deleted_principals.entra_conditional_access_policy_references_deleted_principals import (
                entra_conditional_access_policy_references_deleted_principals,
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
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=[deleted_user_id],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                    ),
                    grant_controls=_default_grant_controls(),
                    session_controls=_default_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }
            entra_client.users = {}
            entra_client.groups = []

            check = entra_conditional_access_policy_references_deleted_principals()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                f"references deleted principals: user {deleted_user_id}"
                in result[0].status_extended
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id

    def test_policy_references_deleted_group(self):
        deleted_group_id = str(uuid4())
        policy_id = str(uuid4())
        display_name = "Block Deleted Group"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_references_deleted_principals.entra_conditional_access_policy_references_deleted_principals import (
                entra_conditional_access_policy_references_deleted_principals,
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
                        user_conditions=UsersConditions(
                            included_groups=[deleted_group_id],
                            excluded_groups=[],
                            included_users=[],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                    ),
                    grant_controls=_default_grant_controls(),
                    session_controls=_default_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }
            entra_client.users = {}
            entra_client.groups = []

            check = entra_conditional_access_policy_references_deleted_principals()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                f"references deleted principals: group {deleted_group_id}"
                in result[0].status_extended
            )

    def test_policy_references_deleted_user_in_exclude(self):
        deleted_user_id = str(uuid4())
        policy_id = str(uuid4())
        display_name = "Exclude Deleted User"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_references_deleted_principals.entra_conditional_access_policy_references_deleted_principals import (
                entra_conditional_access_policy_references_deleted_principals,
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
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=["All"],
                            excluded_users=[deleted_user_id],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                    ),
                    grant_controls=_default_grant_controls(),
                    session_controls=_default_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }
            entra_client.users = {}
            entra_client.groups = []

            check = entra_conditional_access_policy_references_deleted_principals()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                f"references deleted principals: user {deleted_user_id}"
                in result[0].status_extended
            )

    def test_policy_references_both_deleted_user_and_group(self):
        deleted_user_id = str(uuid4())
        deleted_group_id = str(uuid4())
        policy_id = str(uuid4())
        display_name = "Multiple Deleted Refs"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_references_deleted_principals.entra_conditional_access_policy_references_deleted_principals import (
                entra_conditional_access_policy_references_deleted_principals,
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
                        user_conditions=UsersConditions(
                            included_groups=[deleted_group_id],
                            excluded_groups=[],
                            included_users=[deleted_user_id],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                    ),
                    grant_controls=_default_grant_controls(),
                    session_controls=_default_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }
            entra_client.users = {}
            entra_client.groups = []

            check = entra_conditional_access_policy_references_deleted_principals()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert f"user {deleted_user_id}" in result[0].status_extended
            assert f"group {deleted_group_id}" in result[0].status_extended

    def test_policy_report_only_references_deleted_user(self):
        deleted_user_id = str(uuid4())
        policy_id = str(uuid4())
        display_name = "Report Only - Deleted User"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_references_deleted_principals.entra_conditional_access_policy_references_deleted_principals import (
                entra_conditional_access_policy_references_deleted_principals,
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
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=[deleted_user_id],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                    ),
                    grant_controls=_default_grant_controls(),
                    session_controls=_default_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                )
            }
            entra_client.users = {}
            entra_client.groups = []

            check = entra_conditional_access_policy_references_deleted_principals()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "report-only mode" in result[0].status_extended
            assert f"user {deleted_user_id}" in result[0].status_extended

    def test_multiple_policies_mixed(self):
        valid_user_id = str(uuid4())
        deleted_user_id = str(uuid4())
        policy_id_pass = str(uuid4())
        policy_id_fail = str(uuid4())
        display_name_pass = "Valid Policy"
        display_name_fail = "Stale Policy"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_references_deleted_principals.entra_conditional_access_policy_references_deleted_principals import (
                entra_conditional_access_policy_references_deleted_principals,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            entra_client.conditional_access_policies = {
                policy_id_pass: ConditionalAccessPolicy(
                    id=policy_id_pass,
                    display_name=display_name_pass,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["All"],
                            excluded_applications=[],
                            included_user_actions=[],
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=[valid_user_id],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                    ),
                    grant_controls=_default_grant_controls(),
                    session_controls=_default_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
                policy_id_fail: ConditionalAccessPolicy(
                    id=policy_id_fail,
                    display_name=display_name_fail,
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["All"],
                            excluded_applications=[],
                            included_user_actions=[],
                        ),
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=[deleted_user_id],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                    ),
                    grant_controls=_default_grant_controls(),
                    session_controls=_default_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                ),
            }
            entra_client.users = {
                valid_user_id: User(
                    id=valid_user_id,
                    name="Valid User",
                    on_premises_sync_enabled=False,
                    directory_roles_ids=[],
                    is_mfa_capable=True,
                    account_enabled=True,
                    authentication_methods=["password"],
                    user_type="Member",
                )
            }
            entra_client.groups = []

            check = entra_conditional_access_policy_references_deleted_principals()
            result = check.execute()
            assert len(result) == 2

            pass_results = [r for r in result if r.status == "PASS"]
            fail_results = [r for r in result if r.status == "FAIL"]

            assert len(pass_results) == 1
            assert len(fail_results) == 1
            assert pass_results[0].resource_name == display_name_pass
            assert fail_results[0].resource_name == display_name_fail

    def test_special_user_values_not_flagged(self):
        policy_id = str(uuid4())
        display_name = "Special Values Policy"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_references_deleted_principals.entra_conditional_access_policy_references_deleted_principals import (
                entra_conditional_access_policy_references_deleted_principals,
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
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=["All", "None", "GuestsOrExternalUsers"],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                    ),
                    grant_controls=_default_grant_controls(),
                    session_controls=_default_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }
            entra_client.users = {}
            entra_client.groups = []

            check = entra_conditional_access_policy_references_deleted_principals()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {display_name} does not reference any deleted users, groups, or roles."
            )
