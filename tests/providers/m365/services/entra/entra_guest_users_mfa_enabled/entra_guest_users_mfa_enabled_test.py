from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    ApplicationsConditions,
    ConditionalAccessGrantControl,
    ConditionalAccessPolicy,
    ConditionalAccessPolicyState,
    Conditions,
    GrantControlOperator,
    GrantControls,
    GuestOrExternalUserType,
    GuestsOrExternalUsers,
    PersistentBrowser,
    SessionControls,
    SignInFrequency,
    SignInFrequencyInterval,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE = "prowler.providers.m365.services.entra.entra_guest_users_mfa_enabled.entra_guest_users_mfa_enabled"

DEFAULT_SESSION_CONTROLS = SessionControls(
    persistent_browser=PersistentBrowser(is_enabled=False, mode="always"),
    sign_in_frequency=SignInFrequency(
        is_enabled=False,
        frequency=None,
        type=None,
        interval=SignInFrequencyInterval.EVERY_TIME,
    ),
)

ALL_GUEST_TYPES_LIST = [guest_type for guest_type in GuestOrExternalUserType]


class Test_entra_guest_users_mfa_enabled:
    def test_no_conditional_access_policies(self):
        """No conditional access policies configured: expected FAIL."""
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
            from prowler.providers.m365.services.entra.entra_guest_users_mfa_enabled.entra_guest_users_mfa_enabled import (
                entra_guest_users_mfa_enabled,
            )

            entra_client.conditional_access_policies = {}

            check = entra_guest_users_mfa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces MFA for guest users."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_policy_disabled(self):
        """Policy in DISABLED state: expected to be ignored and return FAIL."""
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
            from prowler.providers.m365.services.entra.entra_guest_users_mfa_enabled.entra_guest_users_mfa_enabled import (
                entra_guest_users_mfa_enabled,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name="Disabled Policy",
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
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.AND,
                        authentication_strength=None,
                    ),
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.DISABLED,
                )
            }

            check = entra_guest_users_mfa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces MFA for guest users."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_policy_all_users_mfa_enabled(self):
        """Enabled policy targeting All users with MFA: expected PASS."""
        policy_id = str(uuid4())
        display_name = "MFA for All Users"
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
            from prowler.providers.m365.services.entra.entra_guest_users_mfa_enabled.entra_guest_users_mfa_enabled import (
                entra_guest_users_mfa_enabled,
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.AND,
                        authentication_strength=None,
                    ),
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_guest_users_mfa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' enforces MFA for guest users."
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id

    def test_policy_report_only(self):
        """Policy in report-only state: expected FAIL with specific message."""
        policy_id = str(uuid4())
        display_name = "Report Only MFA Policy"
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
            from prowler.providers.m365.services.entra.entra_guest_users_mfa_enabled.entra_guest_users_mfa_enabled import (
                entra_guest_users_mfa_enabled,
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.AND,
                        authentication_strength=None,
                    ),
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                )
            }

            check = entra_guest_users_mfa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' reports MFA requirement for guest users but does not enforce it."
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id

    def test_policy_guest_types_mfa_enabled(self):
        """Enabled policy targeting all guest types with MFA: expected PASS."""
        policy_id = str(uuid4())
        display_name = "MFA for Guests"
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
            from prowler.providers.m365.services.entra.entra_guest_users_mfa_enabled.entra_guest_users_mfa_enabled import (
                entra_guest_users_mfa_enabled,
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
                            included_users=[],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                            included_guests_or_external_users=GuestsOrExternalUsers(
                                guest_or_external_user_types=ALL_GUEST_TYPES_LIST,
                            ),
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.AND,
                        authentication_strength=None,
                    ),
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_guest_users_mfa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' enforces MFA for guest users."
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id

    def test_policy_incomplete_guest_types(self):
        """Policy targeting only some guest types: expected FAIL."""
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
            from prowler.providers.m365.services.entra.entra_guest_users_mfa_enabled.entra_guest_users_mfa_enabled import (
                entra_guest_users_mfa_enabled,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name="Partial Guest Policy",
                    conditions=Conditions(
                        application_conditions=ApplicationsConditions(
                            included_applications=["All"],
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
                            included_guests_or_external_users=GuestsOrExternalUsers(
                                guest_or_external_user_types=[
                                    GuestOrExternalUserType.B2B_COLLABORATION_GUEST,
                                    GuestOrExternalUserType.INTERNAL_GUEST,
                                ],
                            ),
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.AND,
                        authentication_strength=None,
                    ),
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_guest_users_mfa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces MFA for guest users."
            )

    def test_policy_excludes_guest_types(self):
        """Policy targeting All users but excluding guest types: expected FAIL."""
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
            from prowler.providers.m365.services.entra.entra_guest_users_mfa_enabled.entra_guest_users_mfa_enabled import (
                entra_guest_users_mfa_enabled,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name="Excludes Guests Policy",
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
                            excluded_guests_or_external_users=GuestsOrExternalUsers(
                                guest_or_external_user_types=[
                                    GuestOrExternalUserType.B2B_COLLABORATION_GUEST,
                                ],
                            ),
                        ),
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.AND,
                        authentication_strength=None,
                    ),
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_guest_users_mfa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces MFA for guest users."
            )

    def test_policy_authentication_strength_mfa(self):
        """Policy with authentication strength instead of built-in MFA control: expected PASS."""
        policy_id = str(uuid4())
        display_name = "Auth Strength MFA Policy"
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
            from prowler.providers.m365.services.entra.entra_guest_users_mfa_enabled.entra_guest_users_mfa_enabled import (
                entra_guest_users_mfa_enabled,
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[],
                        operator=GrantControlOperator.AND,
                        authentication_strength="Multifactor authentication",
                    ),
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_guest_users_mfa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Conditional Access Policy '{display_name}' enforces MFA for guest users."
            )
            assert result[0].resource_name == display_name
            assert result[0].resource_id == policy_id

    def test_policy_no_mfa_grant_control(self):
        """Policy without MFA grant control: expected FAIL."""
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
            from prowler.providers.m365.services.entra.entra_guest_users_mfa_enabled.entra_guest_users_mfa_enabled import (
                entra_guest_users_mfa_enabled,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name="Block Policy",
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
                        built_in_controls=[ConditionalAccessGrantControl.BLOCK],
                        operator=GrantControlOperator.AND,
                        authentication_strength=None,
                    ),
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_guest_users_mfa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces MFA for guest users."
            )

    def test_policy_not_all_applications(self):
        """Policy targeting specific apps instead of All: expected FAIL."""
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
            from prowler.providers.m365.services.entra.entra_guest_users_mfa_enabled.entra_guest_users_mfa_enabled import (
                entra_guest_users_mfa_enabled,
            )

            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name="Specific App MFA Policy",
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
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.AND,
                        authentication_strength=None,
                    ),
                    session_controls=DEFAULT_SESSION_CONTROLS,
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            check = entra_guest_users_mfa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy enforces MFA for guest users."
            )
