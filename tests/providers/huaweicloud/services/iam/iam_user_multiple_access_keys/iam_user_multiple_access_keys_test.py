from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestIAMUserMultipleAccessKeys:
    def test_no_resources(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_user_multiple_access_keys.iam_user_multiple_access_keys.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_user_multiple_access_keys.iam_user_multiple_access_keys import (
                iam_user_multiple_access_keys,
            )

            iam_client.users = []
            iam_client.access_keys = []
            iam_client.access_keys_collected = True
            iam_client.audited_account = "123456789012"

            result = iam_user_multiple_access_keys().execute()
            assert len(result) == 0

    def test_access_keys_not_collected_skips(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_user_multiple_access_keys.iam_user_multiple_access_keys.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_service import IAMUser
            from prowler.providers.huaweicloud.services.iam.iam_user_multiple_access_keys.iam_user_multiple_access_keys import (
                iam_user_multiple_access_keys,
            )

            iam_client.users = [IAMUser(id="user-1", name="alice")]
            iam_client.access_keys = []
            iam_client.access_keys_collected = False
            iam_client.audited_account = "123456789012"

            result = iam_user_multiple_access_keys().execute()
            assert len(result) == 0

    def test_user_single_active_key_passes(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_user_multiple_access_keys.iam_user_multiple_access_keys.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                AccessKey,
                IAMUser,
            )
            from prowler.providers.huaweicloud.services.iam.iam_user_multiple_access_keys.iam_user_multiple_access_keys import (
                iam_user_multiple_access_keys,
            )

            iam_client.users = [IAMUser(id="user-1", name="alice")]
            iam_client.access_keys = [
                AccessKey(access="AK1", user_id="user-1", status="active"),
                AccessKey(access="AK2", user_id="user-1", status="inactive"),
            ]
            iam_client.access_keys_collected = True
            iam_client.audited_account = "123456789012"
            iam_client.region = "cn-north-4"

            result = iam_user_multiple_access_keys().execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "does not have multiple active access keys" in result[0].status_extended
            )

    def test_user_multiple_active_keys_fails(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_user_multiple_access_keys.iam_user_multiple_access_keys.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                AccessKey,
                IAMUser,
            )
            from prowler.providers.huaweicloud.services.iam.iam_user_multiple_access_keys.iam_user_multiple_access_keys import (
                iam_user_multiple_access_keys,
            )

            iam_client.users = [IAMUser(id="user-1", name="alice")]
            iam_client.access_keys = [
                AccessKey(access="AK1", user_id="user-1", status="active"),
                AccessKey(access="AK2", user_id="user-1", status="active"),
            ]
            iam_client.access_keys_collected = True
            iam_client.audited_account = "123456789012"
            iam_client.region = "cn-north-4"

            result = iam_user_multiple_access_keys().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "has 2 active access keys" in result[0].status_extended
