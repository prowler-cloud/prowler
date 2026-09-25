from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestIamUserPasswordNotExpired:
    def test_user_no_expiration_passes(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_user_password_not_expired.iam_user_password_not_expired.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_user_password_not_expired.iam_user_password_not_expired import (
                iam_user_password_not_expired,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                IAMUser,
            )

            user = IAMUser(
                id="user-1",
                name="active-user",
                enabled=True,
                is_domain_owner=False,
            )
            iam_client.users = [user]
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_user_password_not_expired()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "no password expiration" in result[0].status_extended

    def test_user_future_expiration_passes(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_user_password_not_expired.iam_user_password_not_expired.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_user_password_not_expired.iam_user_password_not_expired import (
                iam_user_password_not_expired,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                IAMUser,
            )

            user = IAMUser(
                id="user-1",
                name="active-user",
                enabled=True,
                is_domain_owner=False,
                password_expires_at="2099-12-31T23:59:59.000Z",
            )
            iam_client.users = [user]
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_user_password_not_expired()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "expires at" in result[0].status_extended

    def test_user_past_expiration_fails(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_user_password_not_expired.iam_user_password_not_expired.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_user_password_not_expired.iam_user_password_not_expired import (
                iam_user_password_not_expired,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                IAMUser,
            )

            user = IAMUser(
                id="user-1",
                name="expired-user",
                enabled=True,
                is_domain_owner=False,
                password_expires_at="2020-01-01T00:00:00.000Z",
            )
            iam_client.users = [user]
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_user_password_not_expired()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "expired at" in result[0].status_extended

    def test_root_user_skipped(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_user_password_not_expired.iam_user_password_not_expired.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_user_password_not_expired.iam_user_password_not_expired import (
                iam_user_password_not_expired,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                IAMUser,
            )

            root_user = IAMUser(
                id="123456789012",
                name="root",
                enabled=True,
                is_domain_owner=True,
            )
            iam_client.users = [root_user]
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_user_password_not_expired()
            result = check.execute()

            assert len(result) == 0
