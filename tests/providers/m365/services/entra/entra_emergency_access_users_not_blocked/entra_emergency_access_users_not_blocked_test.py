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

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_emergency_access_users_not_blocked.entra_emergency_access_users_not_blocked"


def _make_policy(
    policy_id,
    excluded_users=None,
    excluded_groups=None,
    state=None,
    grant_controls_list=None,
    included_users=None,
):
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
                included_users=included_users or ["All"],
                excluded_users=excluded_users or [],
                included_roles=[],
                excluded_roles=[],
            ),
        ),
        grant_controls=GrantControls(
            built_in_controls=grant_controls_list
            or [ConditionalAccessGrantControl.MFA],
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


class Test_entra_emergency_access_users_not_blocked:
    def test_no_conditional_access_policies(self):
        """Test MANUAL when there are no Conditional Access policies."""
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
            from prowler.providers.m365.services.entra.entra_emergency_access_users_not_blocked.entra_emergency_access_users_not_blocked import (
                entra_emergency_access_users_not_blocked,
            )

            entra_client.conditional_access_policies = {}

            check = entra_emergency_access_users_not_blocked()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                "No enabled Conditional Access policies found"
                in result[0].status_extended
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Emergency Access Users"
            assert result[0].resource_id == "emergencyAccessUsers"
            assert result[0].location == "global"

    def test_all_policies_disabled(self):
        """Test MANUAL when all Conditional Access policies are disabled."""
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
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_emergency_access_users_not_blocked.entra_emergency_access_users_not_blocked import (
                entra_emergency_access_users_not_blocked,
            )

            entra_client.conditional_access_policies = {
                policy_id: _make_policy(
                    policy_id, state=ConditionalAccessPolicyState.DISABLED
                ),
            }

            check = entra_emergency_access_users_not_blocked()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                "No enabled Conditional Access policies found"
                in result[0].status_extended
            )

    def test_no_emergency_access_users_identified(self):
        """Test MANUAL when no user is excluded from all CA policies."""
        policy_id_1 = str(uuid4())
        policy_id_2 = str(uuid4())
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
            from prowler.providers.m365.services.entra.entra_emergency_access_users_not_blocked.entra_emergency_access_users_not_blocked import (
                entra_emergency_access_users_not_blocked,
            )

            # User-1 excluded from policy 1, user-2 from policy 2 -- no one excluded from all
            entra_client.conditional_access_policies = {
                policy_id_1: _make_policy(policy_id_1, excluded_users=["user-1"]),
                policy_id_2: _make_policy(policy_id_2, excluded_users=["user-2"]),
            }

            check = entra_emergency_access_users_not_blocked()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                "No emergency access users identified" in result[0].status_extended
            )

    def test_emergency_user_not_blocked_excluded_from_blocking_policy(self):
        """Test PASS when emergency access user is excluded from all policies including blocking ones."""
        policy_id_mfa = str(uuid4())
        policy_id_block = str(uuid4())
        ea_user_id = str(uuid4())
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
            from prowler.providers.m365.services.entra.entra_emergency_access_users_not_blocked.entra_emergency_access_users_not_blocked import (
                entra_emergency_access_users_not_blocked,
            )

            entra_client.conditional_access_policies = {
                policy_id_mfa: _make_policy(
                    policy_id_mfa,
                    excluded_users=[ea_user_id],
                    grant_controls_list=[ConditionalAccessGrantControl.MFA],
                ),
                policy_id_block: _make_policy(
                    policy_id_block,
                    excluded_users=[ea_user_id],
                    grant_controls_list=[ConditionalAccessGrantControl.BLOCK],
                ),
            }

            entra_client.users = {
                ea_user_id: User(
                    id=ea_user_id,
                    name="EmergencyAccess1",
                    on_premises_sync_enabled=False,
                    authentication_methods=["fido2SecurityKey"],
                ),
            }

            check = entra_emergency_access_users_not_blocked()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "EmergencyAccess1" in result[0].status_extended
            assert "is not blocked" in result[0].status_extended
            assert result[0].resource_name == "EmergencyAccess1"
            assert result[0].resource_id == ea_user_id

    def test_emergency_user_blocked_by_policy(self):
        """Test FAIL when emergency access user is excluded from non-blocking policies but not from a blocking one."""
        policy_id_mfa_1 = str(uuid4())
        policy_id_mfa_2 = str(uuid4())
        policy_id_block = str(uuid4())
        ea_user_id = str(uuid4())
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
            from prowler.providers.m365.services.entra.entra_emergency_access_users_not_blocked.entra_emergency_access_users_not_blocked import (
                entra_emergency_access_users_not_blocked,
            )

            # User excluded from both MFA policies (identified as emergency access)
            # but NOT excluded from the blocking policy (will be blocked)
            entra_client.conditional_access_policies = {
                policy_id_mfa_1: _make_policy(
                    policy_id_mfa_1,
                    excluded_users=[ea_user_id],
                    grant_controls_list=[ConditionalAccessGrantControl.MFA],
                ),
                policy_id_mfa_2: _make_policy(
                    policy_id_mfa_2,
                    excluded_users=[ea_user_id],
                    grant_controls_list=[
                        ConditionalAccessGrantControl.COMPLIANT_DEVICE
                    ],
                ),
                policy_id_block: _make_policy(
                    policy_id_block,
                    excluded_users=[],
                    grant_controls_list=[ConditionalAccessGrantControl.BLOCK],
                ),
            }

            entra_client.users = {
                ea_user_id: User(
                    id=ea_user_id,
                    name="EmergencyAccess1",
                    on_premises_sync_enabled=False,
                    authentication_methods=["fido2SecurityKey"],
                ),
            }

            check = entra_emergency_access_users_not_blocked()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "EmergencyAccess1" in result[0].status_extended
            assert "is blocked" in result[0].status_extended
            assert f"Policy {policy_id_block[:8]}" in result[0].status_extended

    def test_emergency_user_blocked_by_multiple_policies(self):
        """Test FAIL with multiple blocking policies listed in the status message."""
        policy_id_mfa = str(uuid4())
        policy_id_block_1 = str(uuid4())
        policy_id_block_2 = str(uuid4())
        ea_user_id = str(uuid4())
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
            from prowler.providers.m365.services.entra.entra_emergency_access_users_not_blocked.entra_emergency_access_users_not_blocked import (
                entra_emergency_access_users_not_blocked,
            )

            entra_client.conditional_access_policies = {
                policy_id_mfa: _make_policy(
                    policy_id_mfa,
                    excluded_users=[ea_user_id],
                    grant_controls_list=[ConditionalAccessGrantControl.MFA],
                ),
                policy_id_block_1: _make_policy(
                    policy_id_block_1,
                    excluded_users=[],
                    grant_controls_list=[ConditionalAccessGrantControl.BLOCK],
                ),
                policy_id_block_2: _make_policy(
                    policy_id_block_2,
                    excluded_users=[],
                    grant_controls_list=[ConditionalAccessGrantControl.BLOCK],
                ),
            }

            entra_client.users = {
                ea_user_id: User(
                    id=ea_user_id,
                    name="EmergencyAccess1",
                    on_premises_sync_enabled=False,
                    authentication_methods=["fido2SecurityKey"],
                ),
            }

            check = entra_emergency_access_users_not_blocked()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "EmergencyAccess1" in result[0].status_extended
            assert f"Policy {policy_id_block_1[:8]}" in result[0].status_extended
            assert f"Policy {policy_id_block_2[:8]}" in result[0].status_extended

    def test_emergency_user_no_blocking_policies(self):
        """Test PASS when there are no blocking policies at all."""
        policy_id_1 = str(uuid4())
        policy_id_2 = str(uuid4())
        ea_user_id = str(uuid4())
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
            from prowler.providers.m365.services.entra.entra_emergency_access_users_not_blocked.entra_emergency_access_users_not_blocked import (
                entra_emergency_access_users_not_blocked,
            )

            entra_client.conditional_access_policies = {
                policy_id_1: _make_policy(
                    policy_id_1,
                    excluded_users=[ea_user_id],
                    grant_controls_list=[ConditionalAccessGrantControl.MFA],
                ),
                policy_id_2: _make_policy(
                    policy_id_2,
                    excluded_users=[ea_user_id],
                    grant_controls_list=[
                        ConditionalAccessGrantControl.COMPLIANT_DEVICE
                    ],
                ),
            }

            entra_client.users = {
                ea_user_id: User(
                    id=ea_user_id,
                    name="EmergencyAccess1",
                    on_premises_sync_enabled=False,
                    authentication_methods=[],
                ),
            }

            check = entra_emergency_access_users_not_blocked()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "is not blocked" in result[0].status_extended

    def test_multiple_emergency_users_mixed_results(self):
        """Test mixed results when one user is excluded from blocking policy and another is not."""
        policy_id_mfa = str(uuid4())
        policy_id_block = str(uuid4())
        ea_user_id_1 = str(uuid4())
        ea_user_id_2 = str(uuid4())
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
            from prowler.providers.m365.services.entra.entra_emergency_access_users_not_blocked.entra_emergency_access_users_not_blocked import (
                entra_emergency_access_users_not_blocked,
            )

            # Both users excluded from MFA policy (identified as emergency access)
            # Only user 1 excluded from blocking policy
            entra_client.conditional_access_policies = {
                policy_id_mfa: _make_policy(
                    policy_id_mfa,
                    excluded_users=[ea_user_id_1, ea_user_id_2],
                    grant_controls_list=[ConditionalAccessGrantControl.MFA],
                ),
                policy_id_block: _make_policy(
                    policy_id_block,
                    excluded_users=[ea_user_id_1],
                    grant_controls_list=[ConditionalAccessGrantControl.BLOCK],
                ),
            }

            entra_client.users = {
                ea_user_id_1: User(
                    id=ea_user_id_1,
                    name="EmergencyAccess1",
                    on_premises_sync_enabled=False,
                    authentication_methods=["fido2SecurityKey"],
                ),
                ea_user_id_2: User(
                    id=ea_user_id_2,
                    name="EmergencyAccess2",
                    on_premises_sync_enabled=False,
                    authentication_methods=["mobilePhone"],
                ),
            }

            check = entra_emergency_access_users_not_blocked()
            result = check.execute()

            assert len(result) == 2
            statuses = {r.resource_name: r.status for r in result}
            assert statuses["EmergencyAccess1"] == "PASS"
            assert statuses["EmergencyAccess2"] == "FAIL"

    def test_emergency_user_not_in_users_dict(self):
        """Test that an emergency user excluded from all policies but not in users dict is skipped."""
        policy_id = str(uuid4())
        ea_user_id = str(uuid4())
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
            from prowler.providers.m365.services.entra.entra_emergency_access_users_not_blocked.entra_emergency_access_users_not_blocked import (
                entra_emergency_access_users_not_blocked,
            )

            entra_client.conditional_access_policies = {
                policy_id: _make_policy(policy_id, excluded_users=[ea_user_id]),
            }

            entra_client.users = {}

            check = entra_emergency_access_users_not_blocked()
            result = check.execute()

            assert len(result) == 0

    def test_disabled_policies_ignored(self):
        """Test that disabled policies are not considered for identifying emergency access users."""
        policy_id_enabled = str(uuid4())
        policy_id_disabled = str(uuid4())
        ea_user_id = str(uuid4())
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
            from prowler.providers.m365.services.entra.entra_emergency_access_users_not_blocked.entra_emergency_access_users_not_blocked import (
                entra_emergency_access_users_not_blocked,
            )

            entra_client.conditional_access_policies = {
                policy_id_enabled: _make_policy(
                    policy_id_enabled, excluded_users=[ea_user_id]
                ),
                policy_id_disabled: _make_policy(
                    policy_id_disabled,
                    excluded_users=[],
                    state=ConditionalAccessPolicyState.DISABLED,
                ),
            }

            entra_client.users = {
                ea_user_id: User(
                    id=ea_user_id,
                    name="EmergencyAccess1",
                    on_premises_sync_enabled=False,
                    authentication_methods=["fido2SecurityKey"],
                ),
            }

            check = entra_emergency_access_users_not_blocked()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == "EmergencyAccess1"

    def test_emergency_user_with_reporting_only_blocking_policy(self):
        """Test that report-only blocking policies are still evaluated since they are not disabled."""
        policy_id_mfa = str(uuid4())
        policy_id_reporting_block = str(uuid4())
        ea_user_id = str(uuid4())
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
            from prowler.providers.m365.services.entra.entra_emergency_access_users_not_blocked.entra_emergency_access_users_not_blocked import (
                entra_emergency_access_users_not_blocked,
            )

            entra_client.conditional_access_policies = {
                policy_id_mfa: _make_policy(
                    policy_id_mfa,
                    excluded_users=[ea_user_id],
                    grant_controls_list=[ConditionalAccessGrantControl.MFA],
                ),
                policy_id_reporting_block: _make_policy(
                    policy_id_reporting_block,
                    excluded_users=[ea_user_id],
                    grant_controls_list=[ConditionalAccessGrantControl.BLOCK],
                    state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
                ),
            }

            entra_client.users = {
                ea_user_id: User(
                    id=ea_user_id,
                    name="EmergencyAccess1",
                    on_premises_sync_enabled=False,
                    authentication_methods=["fido2SecurityKey"],
                ),
            }

            check = entra_emergency_access_users_not_blocked()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "is not blocked" in result[0].status_extended

    def test_only_blocking_policies_fallback_identification(self):
        """Test identification fallback when all policies are blocking policies."""
        policy_id_block_1 = str(uuid4())
        policy_id_block_2 = str(uuid4())
        ea_user_id = str(uuid4())
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
            from prowler.providers.m365.services.entra.entra_emergency_access_users_not_blocked.entra_emergency_access_users_not_blocked import (
                entra_emergency_access_users_not_blocked,
            )

            # All policies are blocking -- fallback to using all policies for identification
            entra_client.conditional_access_policies = {
                policy_id_block_1: _make_policy(
                    policy_id_block_1,
                    excluded_users=[ea_user_id],
                    grant_controls_list=[ConditionalAccessGrantControl.BLOCK],
                ),
                policy_id_block_2: _make_policy(
                    policy_id_block_2,
                    excluded_users=[ea_user_id],
                    grant_controls_list=[ConditionalAccessGrantControl.BLOCK],
                ),
            }

            entra_client.users = {
                ea_user_id: User(
                    id=ea_user_id,
                    name="EmergencyAccess1",
                    on_premises_sync_enabled=False,
                    authentication_methods=["fido2SecurityKey"],
                ),
            }

            check = entra_emergency_access_users_not_blocked()
            result = check.execute()

            # User is excluded from all (blocking) policies → identified and not blocked
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "is not blocked" in result[0].status_extended

    def test_emergency_user_blocked_by_specific_user_inclusion(self):
        """Test FAIL when blocking policy includes the emergency user by specific ID (not 'All')."""
        policy_id_mfa = str(uuid4())
        policy_id_block = str(uuid4())
        ea_user_id = str(uuid4())
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
            from prowler.providers.m365.services.entra.entra_emergency_access_users_not_blocked.entra_emergency_access_users_not_blocked import (
                entra_emergency_access_users_not_blocked,
            )

            entra_client.conditional_access_policies = {
                policy_id_mfa: _make_policy(
                    policy_id_mfa,
                    excluded_users=[ea_user_id],
                    grant_controls_list=[ConditionalAccessGrantControl.MFA],
                ),
                policy_id_block: _make_policy(
                    policy_id_block,
                    excluded_users=[],
                    included_users=[ea_user_id],
                    grant_controls_list=[ConditionalAccessGrantControl.BLOCK],
                ),
            }

            entra_client.users = {
                ea_user_id: User(
                    id=ea_user_id,
                    name="EmergencyAccess1",
                    on_premises_sync_enabled=False,
                    authentication_methods=["fido2SecurityKey"],
                ),
            }

            check = entra_emergency_access_users_not_blocked()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "EmergencyAccess1" in result[0].status_extended
            assert "is blocked" in result[0].status_extended

    def test_emergency_user_not_included_in_blocking_policy(self):
        """Test PASS when blocking policy targets specific users that don't include the emergency user."""
        policy_id_mfa = str(uuid4())
        policy_id_block = str(uuid4())
        ea_user_id = str(uuid4())
        other_user_id = str(uuid4())
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
            from prowler.providers.m365.services.entra.entra_emergency_access_users_not_blocked.entra_emergency_access_users_not_blocked import (
                entra_emergency_access_users_not_blocked,
            )

            # Blocking policy targets a different user, not the emergency access user
            entra_client.conditional_access_policies = {
                policy_id_mfa: _make_policy(
                    policy_id_mfa,
                    excluded_users=[ea_user_id],
                    grant_controls_list=[ConditionalAccessGrantControl.MFA],
                ),
                policy_id_block: _make_policy(
                    policy_id_block,
                    excluded_users=[],
                    included_users=[other_user_id],
                    grant_controls_list=[ConditionalAccessGrantControl.BLOCK],
                ),
            }

            entra_client.users = {
                ea_user_id: User(
                    id=ea_user_id,
                    name="EmergencyAccess1",
                    on_premises_sync_enabled=False,
                    authentication_methods=["fido2SecurityKey"],
                ),
            }

            check = entra_emergency_access_users_not_blocked()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "is not blocked" in result[0].status_extended

    def test_blocking_policy_with_no_user_conditions(self):
        """Test PASS when a blocking policy has no user conditions (skipped in evaluation)."""
        policy_id_mfa = str(uuid4())
        policy_id_block = str(uuid4())
        ea_user_id = str(uuid4())
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
            from prowler.providers.m365.services.entra.entra_emergency_access_users_not_blocked.entra_emergency_access_users_not_blocked import (
                entra_emergency_access_users_not_blocked,
            )

            from prowler.providers.m365.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            # Create a blocking policy with no user_conditions
            blocking_policy_no_conditions = ConditionalAccessPolicy(
                id=policy_id_block,
                display_name=f"Policy {policy_id_block[:8]}",
                conditions=Conditions(
                    application_conditions=ApplicationsConditions(
                        included_applications=["All"],
                        excluded_applications=[],
                        included_user_actions=[],
                    ),
                    user_conditions=None,
                ),
                grant_controls=GrantControls(
                    built_in_controls=[ConditionalAccessGrantControl.BLOCK],
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
                state=ConditionalAccessPolicyState.ENABLED,
            )

            entra_client.conditional_access_policies = {
                policy_id_mfa: _make_policy(
                    policy_id_mfa,
                    excluded_users=[ea_user_id],
                    grant_controls_list=[ConditionalAccessGrantControl.MFA],
                ),
                policy_id_block: blocking_policy_no_conditions,
            }

            entra_client.users = {
                ea_user_id: User(
                    id=ea_user_id,
                    name="EmergencyAccess1",
                    on_premises_sync_enabled=False,
                    authentication_methods=["fido2SecurityKey"],
                ),
            }

            check = entra_emergency_access_users_not_blocked()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "is not blocked" in result[0].status_extended
