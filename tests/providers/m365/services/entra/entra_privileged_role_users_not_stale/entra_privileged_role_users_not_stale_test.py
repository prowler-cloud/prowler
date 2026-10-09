from datetime import datetime, timedelta, timezone
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
    PrivilegedUserRoleAssignment,
    PrivilegedUserSignInData,
    SessionControls,
    SignInFrequency,
    SignInFrequencyInterval,
    User,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale"

GLOBAL_ADMIN_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"
PRIV_ROLE_ADMIN_ID = "e8611ab8-c189-46e8-94e1-60213ab1f814"


def _make_policy(policy_id, excluded_users=None, state=None):
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
                excluded_groups=[],
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


def _setup_mock():
    """Return a mock entra_client suitable for the stale check tests."""
    entra_client = mock.MagicMock()
    entra_client.audited_tenant = "audited_tenant"
    entra_client.audited_domain = DOMAIN
    entra_client.users_error = None
    entra_client.privileged_users_sign_in_error = None
    entra_client.pim_eligible_error = None
    entra_client.audit_config = {"stale_privileged_account_days": 90}
    entra_client.conditional_access_policies = {}
    entra_client.privileged_users_roles = {}
    entra_client.privileged_users_sign_in_data = {}
    entra_client.users = {}
    return entra_client


class Test_entra_privileged_role_users_not_stale:
    def test_users_error(self):
        """MANUAL when users could not be loaded."""
        entra_client = _setup_mock()
        entra_client.users_error = "Insufficient privileges"

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Insufficient privileges" in result[0].status_extended
            assert result[0].resource_name == "Privileged Users"

    def test_sign_in_tenant_error_p1_missing(self):
        """MANUAL when P1 licence is missing."""
        entra_client = _setup_mock()
        entra_client.privileged_users_sign_in_error = (
            "Cannot evaluate stale privileged accounts: user sign-in "
            "activity requires a Microsoft Entra ID P1 or P2 licence."
        )

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "P1 or P2" in result[0].status_extended

    def test_no_tier0_users(self):
        """PASS when no users hold Tier 0 roles."""
        entra_client = _setup_mock()

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "No users hold Tier 0 roles" in result[0].status_extended

    def test_user_recently_signed_in_pass(self):
        """PASS when the user signed in within the threshold."""
        user_id = str(uuid4())
        entra_client = _setup_mock()

        last_sign_in = datetime.now(timezone.utc) - timedelta(days=10)

        entra_client.users = {
            user_id: User(
                id=user_id,
                name="Active Admin",
                user_principal_name="activeadmin@contoso.com",
                on_premises_sync_enabled=False,
                directory_roles_ids=[GLOBAL_ADMIN_ROLE_ID],
                account_enabled=True,
            ),
        }
        entra_client.privileged_users_roles = {
            user_id: [
                PrivilegedUserRoleAssignment(
                    role_template_id=GLOBAL_ADMIN_ROLE_ID,
                    assignment_type="active",
                ),
            ],
        }
        entra_client.privileged_users_sign_in_data = {
            user_id: PrivilegedUserSignInData(
                last_successful_sign_in=last_sign_in,
            ),
        }

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "Active Admin" in result[0].status_extended
            assert "Global Administrator (active)" in result[0].status_extended
            assert result[0].resource_id == user_id

    def test_user_stale_sign_in_fail(self):
        """FAIL when the user signed in beyond the threshold."""
        user_id = str(uuid4())
        entra_client = _setup_mock()

        last_sign_in = datetime.now(timezone.utc) - timedelta(days=120)

        entra_client.users = {
            user_id: User(
                id=user_id,
                name="Old Admin",
                user_principal_name="oldadmin@contoso.com",
                on_premises_sync_enabled=False,
                directory_roles_ids=[GLOBAL_ADMIN_ROLE_ID],
                account_enabled=True,
            ),
        }
        entra_client.privileged_users_roles = {
            user_id: [
                PrivilegedUserRoleAssignment(
                    role_template_id=GLOBAL_ADMIN_ROLE_ID,
                    assignment_type="active",
                ),
            ],
        }
        entra_client.privileged_users_sign_in_data = {
            user_id: PrivilegedUserSignInData(
                last_successful_sign_in=last_sign_in,
            ),
        }

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Old Admin" in result[0].status_extended
            assert "120 days ago" in result[0].status_extended
            assert "threshold 90 days" in result[0].status_extended

    def test_disabled_account_with_tier0_role_fail(self):
        """FAIL when a disabled account still holds a Tier 0 role."""
        user_id = str(uuid4())
        entra_client = _setup_mock()

        entra_client.users = {
            user_id: User(
                id=user_id,
                name="Disabled Admin",
                user_principal_name="disabledadmin@contoso.com",
                on_premises_sync_enabled=False,
                directory_roles_ids=[GLOBAL_ADMIN_ROLE_ID],
                account_enabled=False,
            ),
        }
        entra_client.privileged_users_roles = {
            user_id: [
                PrivilegedUserRoleAssignment(
                    role_template_id=GLOBAL_ADMIN_ROLE_ID,
                    assignment_type="active",
                ),
            ],
        }
        entra_client.privileged_users_sign_in_data = {
            user_id: PrivilegedUserSignInData(
                last_successful_sign_in=datetime.now(timezone.utc) - timedelta(days=5),
            ),
        }

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "disabled" in result[0].status_extended.lower()
            assert "Global Administrator (active)" in result[0].status_extended

    def test_never_signed_in_within_grace_period_pass(self):
        """PASS when user never signed in but was created within the threshold."""
        user_id = str(uuid4())
        entra_client = _setup_mock()

        created = datetime.now(timezone.utc) - timedelta(days=10)

        entra_client.users = {
            user_id: User(
                id=user_id,
                name="New Admin",
                user_principal_name="newadmin@contoso.com",
                on_premises_sync_enabled=False,
                directory_roles_ids=[GLOBAL_ADMIN_ROLE_ID],
                account_enabled=True,
                created_date_time=created,
            ),
        }
        entra_client.privileged_users_roles = {
            user_id: [
                PrivilegedUserRoleAssignment(
                    role_template_id=GLOBAL_ADMIN_ROLE_ID,
                    assignment_type="active",
                ),
            ],
        }
        entra_client.privileged_users_sign_in_data = {
            user_id: PrivilegedUserSignInData(),
        }

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "never signed in" in result[0].status_extended
            assert "grace period" in result[0].status_extended

    def test_never_signed_in_outside_grace_period_fail(self):
        """FAIL when user never signed in and was created outside the threshold."""
        user_id = str(uuid4())
        entra_client = _setup_mock()

        created = datetime.now(timezone.utc) - timedelta(days=180)

        entra_client.users = {
            user_id: User(
                id=user_id,
                name="Abandoned Admin",
                user_principal_name="abandoned@contoso.com",
                on_premises_sync_enabled=False,
                directory_roles_ids=[GLOBAL_ADMIN_ROLE_ID],
                account_enabled=True,
                created_date_time=created,
            ),
        }
        entra_client.privileged_users_roles = {
            user_id: [
                PrivilegedUserRoleAssignment(
                    role_template_id=GLOBAL_ADMIN_ROLE_ID,
                    assignment_type="active",
                ),
            ],
        }
        entra_client.privileged_users_sign_in_data = {
            user_id: PrivilegedUserSignInData(),
        }

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "never signed in" in result[0].status_extended

    def test_break_glass_account_excluded_pass(self):
        """PASS when user is identified as a break glass account."""
        user_id = str(uuid4())
        policy_id = str(uuid4())
        entra_client = _setup_mock()

        entra_client.users = {
            user_id: User(
                id=user_id,
                name="Break Glass 1",
                user_principal_name="bg1@contoso.com",
                on_premises_sync_enabled=False,
                directory_roles_ids=[GLOBAL_ADMIN_ROLE_ID],
                account_enabled=True,
            ),
        }
        entra_client.privileged_users_roles = {
            user_id: [
                PrivilegedUserRoleAssignment(
                    role_template_id=GLOBAL_ADMIN_ROLE_ID,
                    assignment_type="active",
                ),
            ],
        }
        # Stale sign-in — but excluded as break glass
        entra_client.privileged_users_sign_in_data = {
            user_id: PrivilegedUserSignInData(
                last_successful_sign_in=datetime.now(timezone.utc)
                - timedelta(days=365),
            ),
        }
        entra_client.conditional_access_policies = {
            policy_id: _make_policy(policy_id, excluded_users=[user_id]),
        }

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "emergency-access account" in result[0].status_extended

    def test_per_user_sign_in_error_manual(self):
        """MANUAL when a single user's sign-in lookup fails."""
        user_id = str(uuid4())
        entra_client = _setup_mock()

        entra_client.users = {
            user_id: User(
                id=user_id,
                name="Error Admin",
                user_principal_name="erroradmin@contoso.com",
                on_premises_sync_enabled=False,
                directory_roles_ids=[GLOBAL_ADMIN_ROLE_ID],
                account_enabled=True,
            ),
        }
        entra_client.privileged_users_roles = {
            user_id: [
                PrivilegedUserRoleAssignment(
                    role_template_id=GLOBAL_ADMIN_ROLE_ID,
                    assignment_type="active",
                ),
            ],
        }
        entra_client.privileged_users_sign_in_data = {
            user_id: PrivilegedUserSignInData(
                error="Unable to read sign-in activity for user: throttled"
            ),
        }

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "could not be retrieved" in result[0].status_extended

    def test_eligible_role_assignment_pass(self):
        """PASS when user has PIM eligible Tier 0 role and signed in recently."""
        user_id = str(uuid4())
        entra_client = _setup_mock()

        last_sign_in = datetime.now(timezone.utc) - timedelta(days=5)

        entra_client.users = {
            user_id: User(
                id=user_id,
                name="Eligible Admin",
                user_principal_name="eligible@contoso.com",
                on_premises_sync_enabled=False,
                directory_roles_ids=[],
                account_enabled=True,
            ),
        }
        entra_client.privileged_users_roles = {
            user_id: [
                PrivilegedUserRoleAssignment(
                    role_template_id=GLOBAL_ADMIN_ROLE_ID,
                    assignment_type="eligible",
                ),
            ],
        }
        entra_client.privileged_users_sign_in_data = {
            user_id: PrivilegedUserSignInData(
                last_successful_sign_in=last_sign_in,
            ),
        }

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "Global Administrator (eligible)" in result[0].status_extended

    def test_pim_eligible_error_appended_to_status(self):
        """Verify PIM error note is appended to status_extended."""
        user_id = str(uuid4())
        entra_client = _setup_mock()
        entra_client.pim_eligible_error = (
            "Unable to read PIM role eligibility. Eligible (PIM) assignments "
            "could not be read and were not evaluated."
        )

        entra_client.users = {
            user_id: User(
                id=user_id,
                name="Admin",
                user_principal_name="admin@contoso.com",
                on_premises_sync_enabled=False,
                directory_roles_ids=[GLOBAL_ADMIN_ROLE_ID],
                account_enabled=True,
            ),
        }
        entra_client.privileged_users_roles = {
            user_id: [
                PrivilegedUserRoleAssignment(
                    role_template_id=GLOBAL_ADMIN_ROLE_ID,
                    assignment_type="active",
                ),
            ],
        }
        entra_client.privileged_users_sign_in_data = {
            user_id: PrivilegedUserSignInData(
                last_successful_sign_in=datetime.now(timezone.utc) - timedelta(days=5),
            ),
        }

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "Eligible (PIM) assignments could not be read"
                in result[0].status_extended
            )

    def test_fallback_last_sign_in_when_no_successful(self):
        """PASS using lastSignInDateTime when lastSuccessfulSignIn is null."""
        user_id = str(uuid4())
        entra_client = _setup_mock()

        recent = datetime.now(timezone.utc) - timedelta(days=10)

        entra_client.users = {
            user_id: User(
                id=user_id,
                name="Fallback Admin",
                user_principal_name="fallback@contoso.com",
                on_premises_sync_enabled=False,
                directory_roles_ids=[GLOBAL_ADMIN_ROLE_ID],
                account_enabled=True,
            ),
        }
        entra_client.privileged_users_roles = {
            user_id: [
                PrivilegedUserRoleAssignment(
                    role_template_id=GLOBAL_ADMIN_ROLE_ID,
                    assignment_type="active",
                ),
            ],
        }
        entra_client.privileged_users_sign_in_data = {
            user_id: PrivilegedUserSignInData(
                last_successful_sign_in=None,
                last_sign_in=recent,
                last_non_interactive_sign_in=recent - timedelta(days=2),
            ),
        }

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "Fallback Admin" in result[0].status_extended

    def test_multiple_users_mixed_results(self):
        """Mixed PASS/FAIL for multiple privileged users."""
        active_id = str(uuid4())
        stale_id = str(uuid4())
        entra_client = _setup_mock()

        entra_client.users = {
            active_id: User(
                id=active_id,
                name="Active Admin",
                user_principal_name="active@contoso.com",
                on_premises_sync_enabled=False,
                directory_roles_ids=[GLOBAL_ADMIN_ROLE_ID],
                account_enabled=True,
            ),
            stale_id: User(
                id=stale_id,
                name="Stale Admin",
                user_principal_name="stale@contoso.com",
                on_premises_sync_enabled=False,
                directory_roles_ids=[PRIV_ROLE_ADMIN_ID],
                account_enabled=True,
            ),
        }
        entra_client.privileged_users_roles = {
            active_id: [
                PrivilegedUserRoleAssignment(
                    role_template_id=GLOBAL_ADMIN_ROLE_ID,
                    assignment_type="active",
                ),
            ],
            stale_id: [
                PrivilegedUserRoleAssignment(
                    role_template_id=PRIV_ROLE_ADMIN_ID,
                    assignment_type="active",
                ),
            ],
        }
        entra_client.privileged_users_sign_in_data = {
            active_id: PrivilegedUserSignInData(
                last_successful_sign_in=datetime.now(timezone.utc) - timedelta(days=5),
            ),
            stale_id: PrivilegedUserSignInData(
                last_successful_sign_in=datetime.now(timezone.utc)
                - timedelta(days=200),
            ),
        }

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 2
            statuses = {r.resource_name: r.status for r in result}
            assert statuses["Active Admin"] == "PASS"
            assert statuses["Stale Admin"] == "FAIL"

    def test_multiple_tier0_roles_listed(self):
        """Verify all Tier 0 roles appear in status_extended."""
        user_id = str(uuid4())
        entra_client = _setup_mock()

        entra_client.users = {
            user_id: User(
                id=user_id,
                name="Multi-Role Admin",
                user_principal_name="multirole@contoso.com",
                on_premises_sync_enabled=False,
                directory_roles_ids=[GLOBAL_ADMIN_ROLE_ID, PRIV_ROLE_ADMIN_ID],
                account_enabled=True,
            ),
        }
        entra_client.privileged_users_roles = {
            user_id: [
                PrivilegedUserRoleAssignment(
                    role_template_id=GLOBAL_ADMIN_ROLE_ID,
                    assignment_type="active",
                ),
                PrivilegedUserRoleAssignment(
                    role_template_id=PRIV_ROLE_ADMIN_ID,
                    assignment_type="eligible",
                ),
            ],
        }
        entra_client.privileged_users_sign_in_data = {
            user_id: PrivilegedUserSignInData(
                last_successful_sign_in=datetime.now(timezone.utc) - timedelta(days=5),
            ),
        }

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "Global Administrator (active)" in result[0].status_extended
            assert (
                "Privileged Role Administrator (eligible)" in result[0].status_extended
            )

    def test_never_signed_in_no_created_date_fail(self):
        """FAIL when user never signed in and created_date_time is None."""
        user_id = str(uuid4())
        entra_client = _setup_mock()

        entra_client.users = {
            user_id: User(
                id=user_id,
                name="Unknown Date Admin",
                user_principal_name="unknowndate@contoso.com",
                on_premises_sync_enabled=False,
                directory_roles_ids=[GLOBAL_ADMIN_ROLE_ID],
                account_enabled=True,
                created_date_time=None,
            ),
        }
        entra_client.privileged_users_roles = {
            user_id: [
                PrivilegedUserRoleAssignment(
                    role_template_id=GLOBAL_ADMIN_ROLE_ID,
                    assignment_type="active",
                ),
            ],
        }
        entra_client.privileged_users_sign_in_data = {
            user_id: PrivilegedUserSignInData(),
        }

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "never signed in" in result[0].status_extended
            assert "creation date unknown" in result[0].status_extended

    def test_no_sign_in_data_entry_for_user(self):
        """FAIL when user has no entry in privileged_users_sign_in_data (None sign_in_data)."""
        user_id = str(uuid4())
        entra_client = _setup_mock()

        created = datetime.now(timezone.utc) - timedelta(days=200)

        entra_client.users = {
            user_id: User(
                id=user_id,
                name="Missing Data Admin",
                user_principal_name="missingdata@contoso.com",
                on_premises_sync_enabled=False,
                directory_roles_ids=[GLOBAL_ADMIN_ROLE_ID],
                account_enabled=True,
                created_date_time=created,
            ),
        }
        entra_client.privileged_users_roles = {
            user_id: [
                PrivilegedUserRoleAssignment(
                    role_template_id=GLOBAL_ADMIN_ROLE_ID,
                    assignment_type="active",
                ),
            ],
        }
        # No entry for user_id in sign_in_data at all
        entra_client.privileged_users_sign_in_data = {}

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "never signed in" in result[0].status_extended

    def test_user_in_roles_but_not_in_users_dict_skipped(self):
        """No finding emitted when user is in privileged_users_roles but not in users."""
        user_id = str(uuid4())
        entra_client = _setup_mock()

        entra_client.users = {}  # User not in the directory listing
        entra_client.privileged_users_roles = {
            user_id: [
                PrivilegedUserRoleAssignment(
                    role_template_id=GLOBAL_ADMIN_ROLE_ID,
                    assignment_type="active",
                ),
            ],
        }
        entra_client.privileged_users_sign_in_data = {
            user_id: PrivilegedUserSignInData(
                last_successful_sign_in=datetime.now(timezone.utc) - timedelta(days=5),
            ),
        }

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 0

    def test_break_glass_never_signed_in(self):
        """PASS for break glass account that has never signed in (last_str = 'never')."""
        user_id = str(uuid4())
        policy_id = str(uuid4())
        entra_client = _setup_mock()

        entra_client.users = {
            user_id: User(
                id=user_id,
                name="Break Glass Never",
                user_principal_name="bgnever@contoso.com",
                on_premises_sync_enabled=False,
                directory_roles_ids=[GLOBAL_ADMIN_ROLE_ID],
                account_enabled=True,
            ),
        }
        entra_client.privileged_users_roles = {
            user_id: [
                PrivilegedUserRoleAssignment(
                    role_template_id=GLOBAL_ADMIN_ROLE_ID,
                    assignment_type="active",
                ),
            ],
        }
        # No sign-in data → never signed in
        entra_client.privileged_users_sign_in_data = {
            user_id: PrivilegedUserSignInData(),
        }
        entra_client.conditional_access_policies = {
            policy_id: _make_policy(policy_id, excluded_users=[user_id]),
        }

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "emergency-access account" in result[0].status_extended
            assert "last sign-in never" in result[0].status_extended

    def test_fallback_only_non_interactive_sign_in(self):
        """PASS using only lastNonInteractiveSignInDateTime when others are null."""
        user_id = str(uuid4())
        entra_client = _setup_mock()

        recent = datetime.now(timezone.utc) - timedelta(days=15)

        entra_client.users = {
            user_id: User(
                id=user_id,
                name="NonInteractive Admin",
                user_principal_name="noninteractive@contoso.com",
                on_premises_sync_enabled=False,
                directory_roles_ids=[GLOBAL_ADMIN_ROLE_ID],
                account_enabled=True,
            ),
        }
        entra_client.privileged_users_roles = {
            user_id: [
                PrivilegedUserRoleAssignment(
                    role_template_id=GLOBAL_ADMIN_ROLE_ID,
                    assignment_type="active",
                ),
            ],
        }
        entra_client.privileged_users_sign_in_data = {
            user_id: PrivilegedUserSignInData(
                last_successful_sign_in=None,
                last_sign_in=None,
                last_non_interactive_sign_in=recent,
            ),
        }

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "NonInteractive Admin" in result[0].status_extended

    def test_custom_threshold_days(self):
        """PASS/FAIL boundary respects custom stale_privileged_account_days."""
        user_id = str(uuid4())
        entra_client = _setup_mock()
        entra_client.audit_config = {"stale_privileged_account_days": 30}

        # Signed in 45 days ago → stale at 30-day threshold
        last_sign_in = datetime.now(timezone.utc) - timedelta(days=45)

        entra_client.users = {
            user_id: User(
                id=user_id,
                name="Custom Threshold Admin",
                user_principal_name="custom@contoso.com",
                on_premises_sync_enabled=False,
                directory_roles_ids=[GLOBAL_ADMIN_ROLE_ID],
                account_enabled=True,
            ),
        }
        entra_client.privileged_users_roles = {
            user_id: [
                PrivilegedUserRoleAssignment(
                    role_template_id=GLOBAL_ADMIN_ROLE_ID,
                    assignment_type="active",
                ),
            ],
        }
        entra_client.privileged_users_sign_in_data = {
            user_id: PrivilegedUserSignInData(
                last_successful_sign_in=last_sign_in,
            ),
        }

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "threshold 30 days" in result[0].status_extended
            assert "45 days ago" in result[0].status_extended

    def test_break_glass_not_excluded_from_all_policies(self):
        """User excluded from only some policies is NOT a break glass account."""
        user_id = str(uuid4())
        policy_id_1 = str(uuid4())
        policy_id_2 = str(uuid4())
        entra_client = _setup_mock()

        entra_client.users = {
            user_id: User(
                id=user_id,
                name="Partial Exclude Admin",
                user_principal_name="partial@contoso.com",
                on_premises_sync_enabled=False,
                directory_roles_ids=[GLOBAL_ADMIN_ROLE_ID],
                account_enabled=True,
            ),
        }
        entra_client.privileged_users_roles = {
            user_id: [
                PrivilegedUserRoleAssignment(
                    role_template_id=GLOBAL_ADMIN_ROLE_ID,
                    assignment_type="active",
                ),
            ],
        }
        # Stale sign-in
        entra_client.privileged_users_sign_in_data = {
            user_id: PrivilegedUserSignInData(
                last_successful_sign_in=datetime.now(timezone.utc)
                - timedelta(days=200),
            ),
        }
        # Excluded from policy 1 but NOT from policy 2 → not break glass
        entra_client.conditional_access_policies = {
            policy_id_1: _make_policy(policy_id_1, excluded_users=[user_id]),
            policy_id_2: _make_policy(policy_id_2, excluded_users=[]),
        }

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "emergency-access" not in result[0].status_extended

    def test_disabled_account_eligible_role_fail(self):
        """FAIL when a disabled account holds an eligible (PIM) Tier 0 role."""
        user_id = str(uuid4())
        entra_client = _setup_mock()

        entra_client.users = {
            user_id: User(
                id=user_id,
                name="Disabled Eligible",
                user_principal_name="disabledeligible@contoso.com",
                on_premises_sync_enabled=False,
                directory_roles_ids=[],
                account_enabled=False,
            ),
        }
        entra_client.privileged_users_roles = {
            user_id: [
                PrivilegedUserRoleAssignment(
                    role_template_id=GLOBAL_ADMIN_ROLE_ID,
                    assignment_type="eligible",
                ),
            ],
        }
        entra_client.privileged_users_sign_in_data = {
            user_id: PrivilegedUserSignInData(
                last_successful_sign_in=datetime.now(timezone.utc) - timedelta(days=5),
            ),
        }

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
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            check = entra_privileged_role_users_not_stale()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "disabled" in result[0].status_extended.lower()
            assert "Global Administrator (eligible)" in result[0].status_extended
