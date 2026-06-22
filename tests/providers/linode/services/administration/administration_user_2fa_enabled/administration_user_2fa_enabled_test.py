from unittest import mock

from prowler.providers.linode.services.administration.administration_service import (
    User,
)
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_administration_user_2fa_enabled:
    def test_no_users(self):
        administration_client = mock.MagicMock()
        administration_client.users = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.administration.administration_user_2fa_enabled.administration_user_2fa_enabled.administration_client",
                new=administration_client,
            ),
        ):
            from prowler.providers.linode.services.administration.administration_user_2fa_enabled.administration_user_2fa_enabled import (
                administration_user_2fa_enabled,
            )

            check = administration_user_2fa_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_user_with_2fa(self):
        administration_client = mock.MagicMock()
        administration_client.users = [
            User(
                username="admin",
                email="admin@example.com",
                tfa_enabled=True,
                restricted=False,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.administration.administration_user_2fa_enabled.administration_user_2fa_enabled.administration_client",
                new=administration_client,
            ),
        ):
            from prowler.providers.linode.services.administration.administration_user_2fa_enabled.administration_user_2fa_enabled import (
                administration_user_2fa_enabled,
            )

            check = administration_user_2fa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == "admin"
            assert result[0].resource_id == "admin"

    def test_user_without_2fa(self):
        administration_client = mock.MagicMock()
        administration_client.users = [
            User(
                username="dev-user",
                email="dev@example.com",
                tfa_enabled=False,
                restricted=True,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.administration.administration_user_2fa_enabled.administration_user_2fa_enabled.administration_client",
                new=administration_client,
            ),
        ):
            from prowler.providers.linode.services.administration.administration_user_2fa_enabled.administration_user_2fa_enabled import (
                administration_user_2fa_enabled,
            )

            check = administration_user_2fa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_name == "dev-user"
            assert result[0].resource_id == "dev-user"
