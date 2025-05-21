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
                )
            }

            check = entra_users_mfa_capable()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "User Test User is not MFA capable."
            assert result[0].resource == {}
            assert result[0].resource_name == "Users"
            assert result[0].resource_id == "users"

    def test_user_mfa_capable(self):
        """User is MFA capable: expected PASS."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

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
                )
            }

            check = entra_users_mfa_capable()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "User Test User is MFA capable."
            assert result[0].resource == {}
            assert result[0].resource_name == "Users"
            assert result[0].resource_id == "users"

    def test_multiple_users(self):
        """Multiple users with different MFA capabilities: expected mixed results."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

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
                ),
                user2_id: User(
                    id=user2_id,
                    name="Test User 2",
                    on_premises_sync_enabled=False,
                    directory_roles_ids=[],
                    is_mfa_capable=False,
                ),
            }

            check = entra_users_mfa_capable()
            result = check.execute()

            assert len(result) == 2
            # First user (MFA capable)
            assert result[0].status == "PASS"
            assert result[0].status_extended == "User Test User 1 is MFA capable."
            # Second user (not MFA capable)
            assert result[1].status == "FAIL"
            assert result[1].status_extended == "User Test User 2 is not MFA capable."
