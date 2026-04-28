from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
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
    User,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_break_glass_account_fido2_security_key_registered.entra_break_glass_account_fido2_security_key_registered"


def _make_policy(policy_id, excluded_users=None, excluded_groups=None, state=None):
    """Create a ConditionalAccessPolicy for testing."""
    from prowler.providers.m365.services.entra.entra_service import (
        ConditionalAccessPolicy,
    )

    return ConditionalAccessPolicy(
        id=policy_id,
        display_name=f"Policy {policy_id[:8]}",
        conditions=Conditions(
            application_conditions=ApplicationsConditions(
                included_applications=["All"],
                excluded_applications=[],
                included_user_actions=[],
            ),
            user_conditions=UsersConditions(
                included_groups=[],
                excluded_groups=excluded_groups or [],
                included_users=["All"],
                excluded_users=excluded_users or [],
                included_roles=[],
                excluded_roles=[],
            ),
        ),
        grant_controls=GrantControls(
            built_in_controls=[ConditionalAccessGrantControl.MFA],
            operator=GrantControlOperator.AND,
        ),
        session_controls=SessionControls(
            persistent_browser=PersistentBrowser(is_enabled=False, mode="always"),
            sign_in_frequency=SignInFrequency(
                is_enabled=False,
                frequency=None,
                type=None,
                interval=SignInFrequencyInterval.EVERY_TIME,
            ),
        ),
        state=state or ConditionalAccessPolicyState.ENABLED,
    )


class Test_entra_break_glass_account_fido2_security_key_registered:
    def test_no_conditional_access_policies(self):
        """Test MANUAL when there are no Conditional Access policies."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.user_registration_details_error = None

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
            from prowler.providers.m365.services.entra.entra_break_glass_account_fido2_security_key_registered.entra_break_glass_account_fido2_security_key_registered import (
                entra_break_glass_account_fido2_security_key_registered,
            )

            entra_client.conditional_access_policies = {}

            check = entra_break_glass_account_fido2_security_key_registered()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                "No enabled Conditional Access policies found"
                in result[0].status_extended
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Break Glass Accounts"
            assert result[0].resource_id == "breakGlassAccounts"
            assert result[0].location == "global"

    def test_all_policies_disabled(self):
        """Test MANUAL when all Conditional Access policies are disabled."""
        policy_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.user_registration_details_error = None

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
            from prowler.providers.m365.services.entra.entra_break_glass_account_fido2_security_key_registered.entra_break_glass_account_fido2_security_key_registered import (
                entra_break_glass_account_fido2_security_key_registered,
            )

            entra_client.conditional_access_policies = {
                policy_id: _make_policy(
                    policy_id, state=ConditionalAccessPolicyState.DISABLED
                ),
            }

            check = entra_break_glass_account_fido2_security_key_registered()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                "No enabled Conditional Access policies found"
                in result[0].status_extended
            )

    def test_no_break_glass_accounts_identified(self):
        """Test MANUAL when no user is excluded from all CA policies."""
        policy_id_1 = str(uuid4())
        policy_id_2 = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.user_registration_details_error = None

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
            from prowler.providers.m365.services.entra.entra_break_glass_account_fido2_security_key_registered.entra_break_glass_account_fido2_security_key_registered import (
                entra_break_glass_account_fido2_security_key_registered,
            )

            # User-1 excluded from policy 1, user-2 from policy 2 -- no one excluded from all
            entra_client.conditional_access_policies = {
                policy_id_1: _make_policy(policy_id_1, excluded_users=["user-1"]),
                policy_id_2: _make_policy(policy_id_2, excluded_users=["user-2"]),
            }

            check = entra_break_glass_account_fido2_security_key_registered()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "No break glass accounts identified" in result[0].status_extended

    def test_break_glass_user_with_fido2(self):
        """Test PASS when break glass account has FIDO2 registered."""
        policy_id_1 = str(uuid4())
        policy_id_2 = str(uuid4())
        bg_user_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.user_registration_details_error = None

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
            from prowler.providers.m365.services.entra.entra_break_glass_account_fido2_security_key_registered.entra_break_glass_account_fido2_security_key_registered import (
                entra_break_glass_account_fido2_security_key_registered,
            )

            entra_client.conditional_access_policies = {
                policy_id_1: _make_policy(policy_id_1, excluded_users=[bg_user_id]),
                policy_id_2: _make_policy(policy_id_2, excluded_users=[bg_user_id]),
            }

            entra_client.users = {
                bg_user_id: User(
                    id=bg_user_id,
                    name="BreakGlass1",
                    on_premises_sync_enabled=False,
                    authentication_methods=[
                        "fido2SecurityKey",
                        "microsoftAuthenticatorPush",
                    ],
                ),
            }

            check = entra_break_glass_account_fido2_security_key_registered()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "BreakGlass1" in result[0].status_extended
            assert "FIDO2 security key registered" in result[0].status_extended
            assert result[0].resource_name == "BreakGlass1"
            assert result[0].resource_id == bg_user_id

    def test_break_glass_user_without_fido2(self):
        """Test FAIL when break glass account lacks FIDO2."""
        policy_id_1 = str(uuid4())
        policy_id_2 = str(uuid4())
        bg_user_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.user_registration_details_error = None

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
            from prowler.providers.m365.services.entra.entra_break_glass_account_fido2_security_key_registered.entra_break_glass_account_fido2_security_key_registered import (
                entra_break_glass_account_fido2_security_key_registered,
            )

            entra_client.conditional_access_policies = {
                policy_id_1: _make_policy(policy_id_1, excluded_users=[bg_user_id]),
                policy_id_2: _make_policy(policy_id_2, excluded_users=[bg_user_id]),
            }

            entra_client.users = {
                bg_user_id: User(
                    id=bg_user_id,
                    name="BreakGlass1",
                    on_premises_sync_enabled=False,
                    authentication_methods=["mobilePhone", "email"],
                ),
            }

            check = entra_break_glass_account_fido2_security_key_registered()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "BreakGlass1" in result[0].status_extended
            assert (
                "does not have a FIDO2 security key registered"
                in result[0].status_extended
            )

    def test_break_glass_user_with_empty_authentication_methods(self):
        """Test FAIL when break glass account has no authentication methods."""
        policy_id = str(uuid4())
        bg_user_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.user_registration_details_error = None

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
            from prowler.providers.m365.services.entra.entra_break_glass_account_fido2_security_key_registered.entra_break_glass_account_fido2_security_key_registered import (
                entra_break_glass_account_fido2_security_key_registered,
            )

            entra_client.conditional_access_policies = {
                policy_id: _make_policy(policy_id, excluded_users=[bg_user_id]),
            }

            entra_client.users = {
                bg_user_id: User(
                    id=bg_user_id,
                    name="BreakGlass1",
                    on_premises_sync_enabled=False,
                    authentication_methods=[],
                ),
            }

            check = entra_break_glass_account_fido2_security_key_registered()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "does not have a FIDO2 security key registered"
                in result[0].status_extended
            )

    def test_break_glass_user_with_passkey_device_bound(self):
        """Test MANUAL when break glass account has passKeyDeviceBound but not fido2SecurityKey."""
        policy_id_1 = str(uuid4())
        policy_id_2 = str(uuid4())
        bg_user_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.user_registration_details_error = None

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
            from prowler.providers.m365.services.entra.entra_break_glass_account_fido2_security_key_registered.entra_break_glass_account_fido2_security_key_registered import (
                entra_break_glass_account_fido2_security_key_registered,
            )

            entra_client.conditional_access_policies = {
                policy_id_1: _make_policy(policy_id_1, excluded_users=[bg_user_id]),
                policy_id_2: _make_policy(policy_id_2, excluded_users=[bg_user_id]),
            }

            entra_client.users = {
                bg_user_id: User(
                    id=bg_user_id,
                    name="BreakGlass1",
                    on_premises_sync_enabled=False,
                    authentication_methods=["passKeyDeviceBound"],
                ),
            }

            check = entra_break_glass_account_fido2_security_key_registered()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "BreakGlass1" in result[0].status_extended
            assert "device-bound passkey registered" in result[0].status_extended
            assert "cannot be confirmed" in result[0].status_extended

    def test_multiple_break_glass_users_mixed_results(self):
        """Test mixed results when one BG user has FIDO2 and another does not."""
        policy_id_1 = str(uuid4())
        policy_id_2 = str(uuid4())
        bg_user_id_1 = str(uuid4())
        bg_user_id_2 = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.user_registration_details_error = None

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
            from prowler.providers.m365.services.entra.entra_break_glass_account_fido2_security_key_registered.entra_break_glass_account_fido2_security_key_registered import (
                entra_break_glass_account_fido2_security_key_registered,
            )

            entra_client.conditional_access_policies = {
                policy_id_1: _make_policy(
                    policy_id_1, excluded_users=[bg_user_id_1, bg_user_id_2]
                ),
                policy_id_2: _make_policy(
                    policy_id_2, excluded_users=[bg_user_id_1, bg_user_id_2]
                ),
            }

            entra_client.users = {
                bg_user_id_1: User(
                    id=bg_user_id_1,
                    name="BreakGlass1",
                    on_premises_sync_enabled=False,
                    authentication_methods=["fido2SecurityKey"],
                ),
                bg_user_id_2: User(
                    id=bg_user_id_2,
                    name="BreakGlass2",
                    on_premises_sync_enabled=False,
                    authentication_methods=["mobilePhone"],
                ),
            }

            check = entra_break_glass_account_fido2_security_key_registered()
            result = check.execute()

            assert len(result) == 2
            statuses = {r.resource_name: r.status for r in result}
            assert statuses["BreakGlass1"] == "PASS"
            assert statuses["BreakGlass2"] == "FAIL"

    def test_break_glass_user_not_in_users_dict(self):
        """Test that a user excluded from all policies but not in users dict is skipped."""
        policy_id = str(uuid4())
        bg_user_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.user_registration_details_error = None

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
            from prowler.providers.m365.services.entra.entra_break_glass_account_fido2_security_key_registered.entra_break_glass_account_fido2_security_key_registered import (
                entra_break_glass_account_fido2_security_key_registered,
            )

            entra_client.conditional_access_policies = {
                policy_id: _make_policy(policy_id, excluded_users=[bg_user_id]),
            }

            # User not present in the users dict
            entra_client.users = {}

            check = entra_break_glass_account_fido2_security_key_registered()
            result = check.execute()

            assert len(result) == 0

    def test_disabled_policies_ignored(self):
        """Test that disabled policies are not considered for identifying break glass accounts."""
        policy_id_enabled = str(uuid4())
        policy_id_disabled = str(uuid4())
        bg_user_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.user_registration_details_error = None

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
            from prowler.providers.m365.services.entra.entra_break_glass_account_fido2_security_key_registered.entra_break_glass_account_fido2_security_key_registered import (
                entra_break_glass_account_fido2_security_key_registered,
            )

            # User excluded from the enabled policy but not the disabled one
            entra_client.conditional_access_policies = {
                policy_id_enabled: _make_policy(
                    policy_id_enabled, excluded_users=[bg_user_id]
                ),
                policy_id_disabled: _make_policy(
                    policy_id_disabled,
                    excluded_users=[],
                    state=ConditionalAccessPolicyState.DISABLED,
                ),
            }

            entra_client.users = {
                bg_user_id: User(
                    id=bg_user_id,
                    name="BreakGlass1",
                    on_premises_sync_enabled=False,
                    authentication_methods=["fido2SecurityKey"],
                ),
            }

            check = entra_break_glass_account_fido2_security_key_registered()
            result = check.execute()

            # Only 1 enabled policy and user is excluded from it → break glass user identified
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == "BreakGlass1"

    def test_user_registration_details_permission_error(self):
        """Test FAIL when there's a permission error reading user registration details."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.user_registration_details_error = "Insufficient privileges to read user registration details. Required permission: AuditLog.Read.All"

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
            from prowler.providers.m365.services.entra.entra_break_glass_account_fido2_security_key_registered.entra_break_glass_account_fido2_security_key_registered import (
                entra_break_glass_account_fido2_security_key_registered,
            )

            policy_id = str(uuid4())
            bg_user_id = str(uuid4())

            entra_client.conditional_access_policies = {
                policy_id: _make_policy(policy_id, excluded_users=[bg_user_id]),
            }
            entra_client.users = {
                bg_user_id: User(
                    id=bg_user_id,
                    name="BreakGlass1",
                    on_premises_sync_enabled=False,
                    authentication_methods=[],
                ),
            }

            check = entra_break_glass_account_fido2_security_key_registered()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "Cannot verify FIDO2 security key registration"
                in result[0].status_extended
            )
            assert "AuditLog.Read.All" in result[0].status_extended
            assert result[0].resource_name == "Break Glass Accounts"
            assert result[0].resource_id == "breakGlassAccounts"
