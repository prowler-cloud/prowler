from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestIamUserDisabled:
    def test_enabled_user_passes(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_user_disabled.iam_user_disabled.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_service import IAMUser
            from prowler.providers.huaweicloud.services.iam.iam_user_disabled.iam_user_disabled import (
                iam_user_disabled,
            )

            user = IAMUser(
                id="user-1",
                name="active-user",
                enabled=True,
            )
            iam_client.users = [user]
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_user_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "is enabled" in result[0].status_extended

    def test_disabled_user_fails(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_user_disabled.iam_user_disabled.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_service import IAMUser
            from prowler.providers.huaweicloud.services.iam.iam_user_disabled.iam_user_disabled import (
                iam_user_disabled,
            )

            user = IAMUser(
                id="user-1",
                name="inactive-user",
                enabled=False,
            )
            iam_client.users = [user]
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_user_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "is disabled" in result[0].status_extended

    def test_no_users(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_user_disabled.iam_user_disabled.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_user_disabled.iam_user_disabled import (
                iam_user_disabled,
            )

            iam_client.users = []
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_user_disabled()
            result = check.execute()

            assert len(result) == 0
