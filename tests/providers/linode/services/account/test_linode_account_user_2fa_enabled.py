from unittest import mock
from unittest.mock import MagicMock, patch

from prowler.providers.linode.services.account.account_service import (
    User,
)


def mock_provider():
    provider = MagicMock()
    provider.type = "linode"
    return provider


class TestLinodeAccountUser2faEnabled:
    def test_user_with_2fa(self):
        account_client = mock.MagicMock
        account_client.users = [
            User(
                username="admin",
                email="admin@example.com",
                tfa_enabled=True,
                restricted=False,
            )
        ]

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider(),
            ),
            patch(
                "prowler.providers.linode.services.account.account_user_2fa_enabled.account_user_2fa_enabled.account_client",
                new=account_client,
            ),
        ):
            from prowler.providers.linode.services.account.account_user_2fa_enabled.account_user_2fa_enabled import (
                account_user_2fa_enabled,
            )

            check = account_user_2fa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_user_without_2fa(self):
        account_client = mock.MagicMock
        account_client.users = [
            User(
                username="dev-user",
                email="dev@example.com",
                tfa_enabled=False,
                restricted=True,
            )
        ]

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider(),
            ),
            patch(
                "prowler.providers.linode.services.account.account_user_2fa_enabled.account_user_2fa_enabled.account_client",
                new=account_client,
            ),
        ):
            from prowler.providers.linode.services.account.account_user_2fa_enabled.account_user_2fa_enabled import (
                account_user_2fa_enabled,
            )

            check = account_user_2fa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_no_users(self):
        account_client = mock.MagicMock
        account_client.users = []

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider(),
            ),
            patch(
                "prowler.providers.linode.services.account.account_user_2fa_enabled.account_user_2fa_enabled.account_client",
                new=account_client,
            ),
        ):
            from prowler.providers.linode.services.account.account_user_2fa_enabled.account_user_2fa_enabled import (
                account_user_2fa_enabled,
            )

            check = account_user_2fa_enabled()
            result = check.execute()

            assert len(result) == 0
