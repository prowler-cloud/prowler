"""Tests for the entra_conditional_access_policy_directory_sync_account_excluded check."""

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

DIRECTORY_SYNC_ROLE_TEMPLATE_ID = "d29b2b05-8046-44ba-8758-1e26182fcf32"

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_conditional_access_policy_directory_sync_account_excluded.entra_conditional_access_policy_directory_sync_account_excluded"


def _default_session_controls():
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


def _default_grant_controls():
    """Return default grant controls requiring MFA for test policies."""
    return GrantControls(
        built_in_controls=[ConditionalAccessGrantControl.MFA],
        operator=GrantControlOperator.AND,
        authentication_strength=None,
    )


class Test_entra_conditional_access_policy_directory_sync_account_excluded:
    """Test class for Directory Sync Account exclusion check."""

    def test_no_conditional_access_policies(self):
        """Test PASS when no Conditional Access policies exist."""
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_directory_sync_account_excluded.entra_conditional_access_policy_directory_sync_account_excluded import (
                entra_conditional_access_policy_directory_sync_account_excluded,
            )

            entra_client.conditional_access_policies = {}

            check = entra_conditional_access_policy_directory_sync_account_excluded()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy targets all users and all cloud apps, so no Directory Synchronization Accounts exclusion is needed."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_policy_disabled(self):
        """Test PASS when only a disabled policy exists targeting all users and apps."""
        policy_id = str(uuid4())
        display_name = "Require MFA for All Users"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_directory_sync_account_excluded.entra_conditional_access_policy_directory_sync_account_excluded import (
                entra_conditional_access_policy_directory_sync_account_excluded,
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

            check = entra_conditional_access_policy_directory_sync_account_excluded()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy targets all users and all cloud apps, so no Directory Synchronization Accounts exclusion is needed."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert result[0].location == "global"

    def test_policy_targets_specific_users(self):
        """Test PASS when the policy targets specific users, not all users."""
        policy_id = str(uuid4())
        display_name = "Require MFA for Admins"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_directory_sync_account_excluded.entra_conditional_access_policy_directory_sync_account_excluded import (
                entra_conditional_access_policy_directory_sync_account_excluded,
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
                            included_groups=["some-group-id"],
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

            check = entra_conditional_access_policy_directory_sync_account_excluded()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy targets all users and all cloud apps, so no Directory Synchronization Accounts exclusion is needed."
            )

    def test_policy_targets_specific_apps(self):
        """Test PASS when the policy targets specific apps, not all apps."""
        policy_id = str(uuid4())
        display_name = "Require MFA for Office 365"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_directory_sync_account_excluded.entra_conditional_access_policy_directory_sync_account_excluded import (
                entra_conditional_access_policy_directory_sync_account_excluded,
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
                            included_applications=["some-app-id"],
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
                        client_app_types=[],
                        user_risk_levels=[],
                    ),
                    grant_controls=_default_grant_controls(),
                    session_controls=_default_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_directory_sync_account_excluded()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy targets all users and all cloud apps, so no Directory Synchronization Accounts exclusion is needed."
            )

    def test_policy_enabled_without_sync_exclusion(self):
        """Test FAIL when an enabled policy targets all users and all apps but does not exclude the sync role."""
        policy_id = str(uuid4())
        display_name = "Require MFA for All Users"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_directory_sync_account_excluded.entra_conditional_access_policy_directory_sync_account_excluded import (
                entra_conditional_access_policy_directory_sync_account_excluded,
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

            check = entra_conditional_access_policy_directory_sync_account_excluded()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {display_name} does not exclude the Directory Synchronization Accounts role, which may break Entra Connect sync."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[policy_id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
            assert result[0].location == "global"

    def test_policy_report_only_without_sync_exclusion(self):
        """Test FAIL when a report-only policy targets all users and apps without excluding the sync role."""
        policy_id = str(uuid4())
        display_name = "Report Only - Require MFA"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_directory_sync_account_excluded.entra_conditional_access_policy_directory_sync_account_excluded import (
                entra_conditional_access_policy_directory_sync_account_excluded,
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

            check = entra_conditional_access_policy_directory_sync_account_excluded()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {display_name} reports excluding the Directory Synchronization Accounts role but does not enforce it."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[policy_id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
            assert result[0].location == "global"

    def test_policy_enabled_with_sync_exclusion(self):
        """Test PASS when an enabled policy targets all users and apps and excludes the sync role."""
        policy_id = str(uuid4())
        display_name = "Require MFA for All Users"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_directory_sync_account_excluded.entra_conditional_access_policy_directory_sync_account_excluded import (
                entra_conditional_access_policy_directory_sync_account_excluded,
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
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[
                                DIRECTORY_SYNC_ROLE_TEMPLATE_ID,
                            ],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                    ),
                    grant_controls=_default_grant_controls(),
                    session_controls=_default_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_directory_sync_account_excluded()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {display_name} excludes the Directory Synchronization Accounts role."
            )
            assert (
                result[0].resource
                == entra_client.conditional_access_policies[policy_id].dict()
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
            assert result[0].location == "global"

    def test_policy_with_sync_role_and_other_excluded_roles(self):
        """Test PASS when the sync role is excluded alongside other roles."""
        policy_id = str(uuid4())
        display_name = "Require MFA for All Users"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_directory_sync_account_excluded.entra_conditional_access_policy_directory_sync_account_excluded import (
                entra_conditional_access_policy_directory_sync_account_excluded,
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
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[
                                "some-other-role-id",
                                DIRECTORY_SYNC_ROLE_TEMPLATE_ID,
                            ],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                    ),
                    grant_controls=_default_grant_controls(),
                    session_controls=_default_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_directory_sync_account_excluded()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {display_name} excludes the Directory Synchronization Accounts role."
            )

    def test_multiple_policies_mixed_results(self):
        """Test multiple policies where one excludes sync role and another does not."""
        policy_id_pass = str(uuid4())
        policy_id_fail = str(uuid4())
        display_name_pass = "MFA Policy - With Exclusion"
        display_name_fail = "MFA Policy - Without Exclusion"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_directory_sync_account_excluded.entra_conditional_access_policy_directory_sync_account_excluded import (
                entra_conditional_access_policy_directory_sync_account_excluded,
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
                            included_users=["All"],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[
                                DIRECTORY_SYNC_ROLE_TEMPLATE_ID,
                            ],
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
                            included_users=["All"],
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

            check = entra_conditional_access_policy_directory_sync_account_excluded()
            result = check.execute()
            assert len(result) == 2

            pass_results = [r for r in result if r.status == "PASS"]
            fail_results = [r for r in result if r.status == "FAIL"]

            assert len(pass_results) == 1
            assert len(fail_results) == 1

            assert pass_results[0].resource_name == display_name_pass
            assert pass_results[0].resource_id == policy_id_pass
            assert (
                pass_results[0].status_extended
                == f"Conditional Access Policy {display_name_pass} excludes the Directory Synchronization Accounts role."
            )

            assert fail_results[0].resource_name == display_name_fail
            assert fail_results[0].resource_id == policy_id_fail
            assert (
                fail_results[0].status_extended
                == f"Conditional Access Policy {display_name_fail} does not exclude the Directory Synchronization Accounts role, which may break Entra Connect sync."
            )

    def test_policy_with_wrong_excluded_role(self):
        """Test FAIL when the policy excludes a different role but not the sync role."""
        policy_id = str(uuid4())
        display_name = "Require MFA for All Users"
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_directory_sync_account_excluded.entra_conditional_access_policy_directory_sync_account_excluded import (
                entra_conditional_access_policy_directory_sync_account_excluded,
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
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=["some-other-role-id"],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                    ),
                    grant_controls=_default_grant_controls(),
                    session_controls=_default_session_controls(),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_conditional_access_policy_directory_sync_account_excluded()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy {display_name} does not exclude the Directory Synchronization Accounts role, which may break Entra Connect sync."
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id
