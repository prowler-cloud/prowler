from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    ALL_GUEST_USER_TYPES,
    ApplicationsConditions,
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    Conditions,
    GuestOrExternalUserType,
    GuestsOrExternalUsers,
    GrantControlOperator,
    GrantControls,
    PersistentBrowser,
    SessionControls,
    SignInFrequency,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_conditional_access_policy_mfa_enforced_for_guest_users.entra_conditional_access_policy_mfa_enforced_for_guest_users"


def build_policy(
    *,
    display_name: str,
    state: ConditionalAccessPolicyState,
    included_applications: list[str] | None = None,
    included_users: list[str] | None = None,
    built_in_controls: list[ConditionalAccessGrantControl] | None = None,
    authentication_strength: str | None = None,
    included_guests_or_external_users: GuestsOrExternalUsers | None = None,
    excluded_guests_or_external_users: GuestsOrExternalUsers | None = None,
):
    """Build a ConditionalAccessPolicy for testing."""
    from prowler.providers.m365.services.entra.entra_service import (
        ConditionalAccessPolicy,
    )

    return ConditionalAccessPolicy(
        id=str(uuid4()),
        display_name=display_name,
        conditions=Conditions(
            application_conditions=ApplicationsConditions(
                included_applications=included_applications or ["All"],
                excluded_applications=[],
                included_user_actions=[],
            ),
            user_conditions=UsersConditions(
                included_groups=[],
                excluded_groups=[],
                included_users=included_users or [],
                excluded_users=[],
                included_roles=[],
                excluded_roles=[],
                included_guests_or_external_users=included_guests_or_external_users,
                excluded_guests_or_external_users=excluded_guests_or_external_users,
            ),
            client_app_types=[],
            user_risk_levels=[],
        ),
        grant_controls=GrantControls(
            built_in_controls=built_in_controls or [],
            operator=GrantControlOperator.OR,
            authentication_strength=authentication_strength,
        ),
        session_controls=SessionControls(
            persistent_browser=PersistentBrowser(is_enabled=False, mode="always"),
            sign_in_frequency=SignInFrequency(
                is_enabled=False,
                frequency=None,
                type=None,
                interval=None,
            ),
        ),
        state=state,
    )


class Test_entra_conditional_access_policy_mfa_enforced_for_guest_users:
    """Tests for the entra_conditional_access_policy_mfa_enforced_for_guest_users check."""

    def test_no_conditional_access_policies(self):
        """Test FAIL when there are no Conditional Access policies."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_mfa_enforced_for_guest_users.entra_conditional_access_policy_mfa_enforced_for_guest_users import (
                entra_conditional_access_policy_mfa_enforced_for_guest_users,
            )

            entra_client.conditional_access_policies = {}

            result = (
                entra_conditional_access_policy_mfa_enforced_for_guest_users().execute()
            )

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires MFA for guest users."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Conditional Access Policies"
            assert result[0].resource_id == "conditionalAccessPolicies"

    def test_disabled_policy_is_skipped(self):
        """Test FAIL when the only matching policy is disabled."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_mfa_enforced_for_guest_users.entra_conditional_access_policy_mfa_enforced_for_guest_users import (
                entra_conditional_access_policy_mfa_enforced_for_guest_users,
            )

            policy = build_policy(
                display_name="MFA for Guests",
                state=ConditionalAccessPolicyState.DISABLED,
                included_users=["GuestsOrExternalUsers"],
                built_in_controls=[ConditionalAccessGrantControl.MFA],
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = (
                entra_conditional_access_policy_mfa_enforced_for_guest_users().execute()
            )

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires MFA for guest users."
            )

    def test_policy_enabled_targeting_all_users_with_mfa(self):
        """Test PASS when an enabled policy targets all users with MFA for all apps."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_mfa_enforced_for_guest_users.entra_conditional_access_policy_mfa_enforced_for_guest_users import (
                entra_conditional_access_policy_mfa_enforced_for_guest_users,
            )

            policy = build_policy(
                display_name="MFA for All Users",
                state=ConditionalAccessPolicyState.ENABLED,
                included_users=["All"],
                built_in_controls=[ConditionalAccessGrantControl.MFA],
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = (
                entra_conditional_access_policy_mfa_enforced_for_guest_users().execute()
            )

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Conditional Access Policy 'MFA for All Users' requires MFA for guest users."
            )
            assert result[0].resource_id == policy.id
            assert result[0].resource_name == "MFA for All Users"

    def test_policy_enabled_targeting_guests_or_external_users(self):
        """Test PASS when an enabled policy specifically targets GuestsOrExternalUsers."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_mfa_enforced_for_guest_users.entra_conditional_access_policy_mfa_enforced_for_guest_users import (
                entra_conditional_access_policy_mfa_enforced_for_guest_users,
            )

            policy = build_policy(
                display_name="MFA for Guest Users",
                state=ConditionalAccessPolicyState.ENABLED,
                included_users=["GuestsOrExternalUsers"],
                built_in_controls=[ConditionalAccessGrantControl.MFA],
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = (
                entra_conditional_access_policy_mfa_enforced_for_guest_users().execute()
            )

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Conditional Access Policy 'MFA for Guest Users' requires MFA for guest users."
            )
            assert result[0].resource_id == policy.id

    def test_policy_enabled_targeting_all_guest_types_via_included_guests(self):
        """Test PASS when policy targets all six guest types via included_guests_or_external_users."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_mfa_enforced_for_guest_users.entra_conditional_access_policy_mfa_enforced_for_guest_users import (
                entra_conditional_access_policy_mfa_enforced_for_guest_users,
            )

            policy = build_policy(
                display_name="MFA for All Guest Types",
                state=ConditionalAccessPolicyState.ENABLED,
                built_in_controls=[ConditionalAccessGrantControl.MFA],
                included_guests_or_external_users=GuestsOrExternalUsers(
                    guest_or_external_user_types=list(ALL_GUEST_USER_TYPES),
                ),
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = (
                entra_conditional_access_policy_mfa_enforced_for_guest_users().execute()
            )

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == policy.id

    def test_policy_with_authentication_strength_passes(self):
        """Test PASS when policy uses authentication strength instead of MFA built-in control."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_mfa_enforced_for_guest_users.entra_conditional_access_policy_mfa_enforced_for_guest_users import (
                entra_conditional_access_policy_mfa_enforced_for_guest_users,
            )

            policy = build_policy(
                display_name="Auth Strength for Guests",
                state=ConditionalAccessPolicyState.ENABLED,
                included_users=["GuestsOrExternalUsers"],
                authentication_strength="Phishing-resistant MFA",
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = (
                entra_conditional_access_policy_mfa_enforced_for_guest_users().execute()
            )

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == policy.id

    def test_policy_only_password_change_fails(self):
        """Test FAIL when the policy only requires password change."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_mfa_enforced_for_guest_users.entra_conditional_access_policy_mfa_enforced_for_guest_users import (
                entra_conditional_access_policy_mfa_enforced_for_guest_users,
            )

            policy = build_policy(
                display_name="Password Change for Guests",
                state=ConditionalAccessPolicyState.ENABLED,
                included_users=["GuestsOrExternalUsers"],
                built_in_controls=[ConditionalAccessGrantControl.PASSWORD_CHANGE],
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = (
                entra_conditional_access_policy_mfa_enforced_for_guest_users().execute()
            )

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires MFA for guest users."
            )

    def test_policy_not_targeting_all_apps_fails(self):
        """Test FAIL when the policy does not target all cloud applications."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_mfa_enforced_for_guest_users.entra_conditional_access_policy_mfa_enforced_for_guest_users import (
                entra_conditional_access_policy_mfa_enforced_for_guest_users,
            )

            policy = build_policy(
                display_name="MFA for Guests Specific App",
                state=ConditionalAccessPolicyState.ENABLED,
                included_applications=["some-specific-app-id"],
                included_users=["GuestsOrExternalUsers"],
                built_in_controls=[ConditionalAccessGrantControl.MFA],
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = (
                entra_conditional_access_policy_mfa_enforced_for_guest_users().execute()
            )

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires MFA for guest users."
            )

    def test_policy_not_targeting_guests_fails(self):
        """Test FAIL when the policy does not target guest users."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_mfa_enforced_for_guest_users.entra_conditional_access_policy_mfa_enforced_for_guest_users import (
                entra_conditional_access_policy_mfa_enforced_for_guest_users,
            )

            policy = build_policy(
                display_name="MFA for Specific Users",
                state=ConditionalAccessPolicyState.ENABLED,
                included_users=[str(uuid4())],
                built_in_controls=[ConditionalAccessGrantControl.MFA],
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = (
                entra_conditional_access_policy_mfa_enforced_for_guest_users().execute()
            )

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires MFA for guest users."
            )

    def test_policy_with_partial_guest_types_fails(self):
        """Test FAIL when policy only targets some guest types but not all six."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_mfa_enforced_for_guest_users.entra_conditional_access_policy_mfa_enforced_for_guest_users import (
                entra_conditional_access_policy_mfa_enforced_for_guest_users,
            )

            policy = build_policy(
                display_name="MFA for Some Guests",
                state=ConditionalAccessPolicyState.ENABLED,
                built_in_controls=[ConditionalAccessGrantControl.MFA],
                included_guests_or_external_users=GuestsOrExternalUsers(
                    guest_or_external_user_types=[
                        GuestOrExternalUserType.B2B_COLLABORATION_GUEST,
                        GuestOrExternalUserType.INTERNAL_GUEST,
                    ],
                ),
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = (
                entra_conditional_access_policy_mfa_enforced_for_guest_users().execute()
            )

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires MFA for guest users."
            )

    def test_policy_with_excluded_guest_types_fails(self):
        """Test FAIL when the policy excludes guest/external user types."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_mfa_enforced_for_guest_users.entra_conditional_access_policy_mfa_enforced_for_guest_users import (
                entra_conditional_access_policy_mfa_enforced_for_guest_users,
            )

            policy = build_policy(
                display_name="MFA for Guests with Exclusions",
                state=ConditionalAccessPolicyState.ENABLED,
                included_users=["All"],
                built_in_controls=[ConditionalAccessGrantControl.MFA],
                excluded_guests_or_external_users=GuestsOrExternalUsers(
                    guest_or_external_user_types=[
                        GuestOrExternalUserType.SERVICE_PROVIDER,
                    ],
                ),
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = (
                entra_conditional_access_policy_mfa_enforced_for_guest_users().execute()
            )

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires MFA for guest users."
            )

    def test_reporting_only_policy_fails_with_detail(self):
        """Test FAIL with detail when the matching policy is in report-only mode."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_mfa_enforced_for_guest_users.entra_conditional_access_policy_mfa_enforced_for_guest_users import (
                entra_conditional_access_policy_mfa_enforced_for_guest_users,
            )

            policy = build_policy(
                display_name="MFA for Guests Report Only",
                state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                included_users=["GuestsOrExternalUsers"],
                built_in_controls=[ConditionalAccessGrantControl.MFA],
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = (
                entra_conditional_access_policy_mfa_enforced_for_guest_users().execute()
            )

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Conditional Access Policy 'MFA for Guests Report Only' targets guest users with MFA but is only in report-only mode."
            )
            assert result[0].resource_id == policy.id
            assert result[0].resource_name == "MFA for Guests Report Only"

    def test_no_application_conditions_fails(self):
        """Test FAIL when the policy has no application conditions."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_mfa_enforced_for_guest_users.entra_conditional_access_policy_mfa_enforced_for_guest_users import (
                entra_conditional_access_policy_mfa_enforced_for_guest_users,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            policy_id = str(uuid4())
            entra_client.conditional_access_policies = {
                policy_id: ConditionalAccessPolicy(
                    id=policy_id,
                    display_name="No App Conditions",
                    conditions=Conditions(
                        application_conditions=None,
                        user_conditions=UsersConditions(
                            included_groups=[],
                            excluded_groups=[],
                            included_users=["GuestsOrExternalUsers"],
                            excluded_users=[],
                            included_roles=[],
                            excluded_roles=[],
                        ),
                        client_app_types=[],
                        user_risk_levels=[],
                    ),
                    grant_controls=GrantControls(
                        built_in_controls=[ConditionalAccessGrantControl.MFA],
                        operator=GrantControlOperator.OR,
                        authentication_strength=None,
                    ),
                    session_controls=SessionControls(
                        persistent_browser=PersistentBrowser(
                            is_enabled=False, mode="always"
                        ),
                        sign_in_frequency=SignInFrequency(
                            is_enabled=False,
                            frequency=None,
                            type=None,
                            interval=None,
                        ),
                    ),
                    state=ConditionalAccessPolicyState.ENABLED,
                )
            }

            result = (
                entra_conditional_access_policy_mfa_enforced_for_guest_users().execute()
            )

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires MFA for guest users."
            )

    def test_no_mfa_grant_control_fails(self):
        """Test FAIL when the policy does not require MFA as a grant control."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_mfa_enforced_for_guest_users.entra_conditional_access_policy_mfa_enforced_for_guest_users import (
                entra_conditional_access_policy_mfa_enforced_for_guest_users,
            )

            policy = build_policy(
                display_name="Compliant Device for Guests",
                state=ConditionalAccessPolicyState.ENABLED,
                included_users=["GuestsOrExternalUsers"],
                built_in_controls=[ConditionalAccessGrantControl.COMPLIANT_DEVICE],
            )
            entra_client.conditional_access_policies = {policy.id: policy}

            result = (
                entra_conditional_access_policy_mfa_enforced_for_guest_users().execute()
            )

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Conditional Access Policy requires MFA for guest users."
            )
