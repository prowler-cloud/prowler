from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import User
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_entra_users_mfa_capable:
    def test_user_not_mfa_capable(self):
        """User is not MFA capable: expected FAIL."""
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
                "prowler.providers.m365.services.entra.entra_users_mfa_capable.entra_users_mfa_capable.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_users_mfa_capable.entra_users_mfa_capable import (
                entra_users_mfa_capable,
            )

            user_id = str(uuid4())
            entra_client.users = {
                user_id: User(
                    id=user_id,
                    name="Test User",
                    on_premises_sync_enabled=False,
                    directory_roles_ids=[],
                    is_mfa_capable=False,
                    account_enabled=True,
                )
            }

            check = entra_users_mfa_capable()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "User Test User is not MFA capable."
            assert result[0].resource == entra_client.users[user_id]
            assert result[0].resource_name == "Test User"
            assert result[0].resource_id == user_id

    def test_user_mfa_capable(self):
        """User is MFA capable: expected PASS."""
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
                "prowler.providers.m365.services.entra.entra_users_mfa_capable.entra_users_mfa_capable.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_users_mfa_capable.entra_users_mfa_capable import (
                entra_users_mfa_capable,
            )

            user_id = str(uuid4())
            entra_client.users = {
                user_id: User(
                    id=user_id,
                    name="Test User",
                    on_premises_sync_enabled=False,
                    directory_roles_ids=[],
                    is_mfa_capable=True,
                    account_enabled=True,
                )
            }

            check = entra_users_mfa_capable()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "User Test User is MFA capable."
            assert result[0].resource == entra_client.users[user_id]
            assert result[0].resource_name == "Test User"
            assert result[0].resource_id == user_id

    def test_multiple_users(self):
        """Multiple users with different MFA capabilities: expected mixed results."""
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
                "prowler.providers.m365.services.entra.entra_users_mfa_capable.entra_users_mfa_capable.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_users_mfa_capable.entra_users_mfa_capable import (
                entra_users_mfa_capable,
            )

            user1_id = str(uuid4())
            user2_id = str(uuid4())
            entra_client.users = {
                user1_id: User(
                    id=user1_id,
                    name="Test User 1",
                    on_premises_sync_enabled=False,
                    directory_roles_ids=[],
                    is_mfa_capable=True,
                    account_enabled=True,
                ),
                user2_id: User(
                    id=user2_id,
                    name="Test User 2",
                    on_premises_sync_enabled=False,
                    directory_roles_ids=[],
                    is_mfa_capable=False,
                    account_enabled=True,
                ),
            }

            check = entra_users_mfa_capable()
            result = check.execute()

            assert len(result) == 2
            # First user (MFA capable)
            assert result[0].status == "PASS"
            assert result[0].status_extended == "User Test User 1 is MFA capable."
            assert result[0].resource == entra_client.users[user1_id]
            assert result[0].resource_name == "Test User 1"
            assert result[0].resource_id == user1_id
            # Second user (not MFA capable)
            assert result[1].status == "FAIL"
            assert result[1].status_extended == "User Test User 2 is not MFA capable."
            assert result[1].resource == entra_client.users[user2_id]
            assert result[1].resource_name == "Test User 2"
            assert result[1].resource_id == user2_id

    def test_disabled_user_not_checked(self):
        """Disabled user should not be checked: expected no results."""
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
                "prowler.providers.m365.services.entra.entra_users_mfa_capable.entra_users_mfa_capable.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_users_mfa_capable.entra_users_mfa_capable import (
                entra_users_mfa_capable,
            )

            user_id = str(uuid4())
            entra_client.users = {
                user_id: User(
                    id=user_id,
                    name="Disabled User",
                    on_premises_sync_enabled=False,
                    directory_roles_ids=[],
                    is_mfa_capable=False,
                    account_enabled=False,  # Disabled user
                )
            }

            check = entra_users_mfa_capable()
            result = check.execute()

            # No results should be returned for disabled users
            assert len(result) == 0

    def test_mixed_enabled_disabled_users(self):
        """Mix of enabled and disabled users: only enabled users should be checked."""
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
                "prowler.providers.m365.services.entra.entra_users_mfa_capable.entra_users_mfa_capable.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_users_mfa_capable.entra_users_mfa_capable import (
                entra_users_mfa_capable,
            )

            enabled_user_id = str(uuid4())
            disabled_user_id = str(uuid4())
            entra_client.users = {
                enabled_user_id: User(
                    id=enabled_user_id,
                    name="Enabled User",
                    on_premises_sync_enabled=False,
                    directory_roles_ids=[],
                    is_mfa_capable=True,
                    account_enabled=True,  # Enabled user
                ),
                disabled_user_id: User(
                    id=disabled_user_id,
                    name="Disabled User",
                    on_premises_sync_enabled=False,
                    directory_roles_ids=[],
                    is_mfa_capable=False,
                    account_enabled=False,  # Disabled user
                ),
            }

            check = entra_users_mfa_capable()
            result = check.execute()

            # Only the enabled user should be checked
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "User Enabled User is MFA capable."
            assert result[0].resource == entra_client.users[enabled_user_id]
            assert result[0].resource_name == "Enabled User"
            assert result[0].resource_id == enabled_user_id

    def test_disabled_guest_user_not_checked(self):
        """Disabled guest user should not be checked: expected no results.

        Regression test for https://github.com/prowler-cloud/prowler/issues/10637.
        CIS 5.2.3.4 evaluates only enabled member users; disabled guests must be skipped
        even when ``account_enabled`` cannot be derived from Exchange Online.
        """
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
                "prowler.providers.m365.services.entra.entra_users_mfa_capable.entra_users_mfa_capable.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_users_mfa_capable.entra_users_mfa_capable import (
                entra_users_mfa_capable,
            )

            user_id = str(uuid4())
            entra_client.users = {
                user_id: User(
                    id=user_id,
                    name="Disabled Guest",
                    on_premises_sync_enabled=False,
                    directory_roles_ids=[],
                    is_mfa_capable=False,
                    account_enabled=False,
                    user_type="Guest",
                )
            }

            check = entra_users_mfa_capable()
            result = check.execute()

            assert len(result) == 0

    def test_enabled_guest_user_not_checked(self):
        """Enabled guest user is out of scope for CIS 5.2.3.4: expected no results."""
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
                "prowler.providers.m365.services.entra.entra_users_mfa_capable.entra_users_mfa_capable.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_users_mfa_capable.entra_users_mfa_capable import (
                entra_users_mfa_capable,
            )

            user_id = str(uuid4())
            entra_client.users = {
                user_id: User(
                    id=user_id,
                    name="Guest User",
                    on_premises_sync_enabled=False,
                    directory_roles_ids=[],
                    is_mfa_capable=False,
                    account_enabled=True,
                    user_type="Guest",
                )
            }

            check = entra_users_mfa_capable()
            result = check.execute()

            assert len(result) == 0

    def test_member_and_guest_users(self):
        """Mix of member and guest users: only member users should be checked."""
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
                "prowler.providers.m365.services.entra.entra_users_mfa_capable.entra_users_mfa_capable.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_users_mfa_capable.entra_users_mfa_capable import (
                entra_users_mfa_capable,
            )

            member_user_id = str(uuid4())
            guest_user_id = str(uuid4())
            entra_client.users = {
                member_user_id: User(
                    id=member_user_id,
                    name="Member User",
                    on_premises_sync_enabled=False,
                    directory_roles_ids=[],
                    is_mfa_capable=False,
                    account_enabled=True,
                    user_type="Member",
                ),
                guest_user_id: User(
                    id=guest_user_id,
                    name="Guest User",
                    on_premises_sync_enabled=False,
                    directory_roles_ids=[],
                    is_mfa_capable=False,
                    account_enabled=True,
                    user_type="Guest",
                ),
            }

            check = entra_users_mfa_capable()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "User Member User is not MFA capable."
            assert result[0].resource == entra_client.users[member_user_id]
            assert result[0].resource_name == "Member User"
            assert result[0].resource_id == member_user_id

    def test_unknown_user_type_is_evaluated(self):
        """Users without a ``user_type`` reported by Microsoft Graph must not be
        silently dropped.

        We only skip users that Graph explicitly reports as ``Guest``; for everyone
        else (including ``user_type=None``) the check still evaluates MFA capability
        so that we never mask findings on accounts whose type cannot be determined.
        """
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
                "prowler.providers.m365.services.entra.entra_users_mfa_capable.entra_users_mfa_capable.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_users_mfa_capable.entra_users_mfa_capable import (
                entra_users_mfa_capable,
            )

            user_id = str(uuid4())
            entra_client.users = {
                user_id: User(
                    id=user_id,
                    name="Test User",
                    on_premises_sync_enabled=False,
                    directory_roles_ids=[],
                    is_mfa_capable=False,
                    account_enabled=True,
                    user_type=None,
                )
            }

            check = entra_users_mfa_capable()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "User Test User is not MFA capable."
            assert result[0].resource == entra_client.users[user_id]
            assert result[0].resource_name == "Test User"
            assert result[0].resource_id == user_id

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
                "prowler.providers.m365.services.entra.entra_users_mfa_capable.entra_users_mfa_capable.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_users_mfa_capable.entra_users_mfa_capable import (
                entra_users_mfa_capable,
            )

            user_id = str(uuid4())
            entra_client.users = {
                user_id: User(
                    id=user_id,
                    name="Test User",
                    on_premises_sync_enabled=False,
                    directory_roles_ids=[],
                    is_mfa_capable=False,
                    account_enabled=True,
                )
            }

            check = entra_users_mfa_capable()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Cannot verify MFA capability for users" in result[0].status_extended
            assert "AuditLog.Read.All" in result[0].status_extended
            assert result[0].resource_name == "User Registration Details"
            assert result[0].resource_id == "userRegistrationDetails"
