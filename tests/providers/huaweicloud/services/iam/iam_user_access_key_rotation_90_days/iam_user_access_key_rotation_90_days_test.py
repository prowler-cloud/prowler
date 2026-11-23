from datetime import datetime, timedelta, timezone
from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestIAMUserAccessKeyRotation90Days:
    def test_no_resources(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_user_access_key_rotation_90_days.iam_user_access_key_rotation_90_days.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_user_access_key_rotation_90_days.iam_user_access_key_rotation_90_days import (
                iam_user_access_key_rotation_90_days,
            )

            iam_client.access_keys = []
            iam_client.audited_account = "123456789012"

            result = iam_user_access_key_rotation_90_days().execute()
            assert len(result) == 0

    def test_recent_access_key_passes(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_user_access_key_rotation_90_days.iam_user_access_key_rotation_90_days.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_service import AccessKey
            from prowler.providers.huaweicloud.services.iam.iam_user_access_key_rotation_90_days.iam_user_access_key_rotation_90_days import (
                iam_user_access_key_rotation_90_days,
            )

            recent = (datetime.now(timezone.utc) - timedelta(days=30)).strftime(
                "%Y-%m-%dT%H:%M:%S.000000Z"
            )
            iam_client.access_keys = [
                AccessKey(
                    access="AKIA123",
                    user_id="user-1",
                    status="active",
                    create_time=recent,
                )
            ]
            iam_client.users = []
            iam_client.audited_account = "123456789012"
            iam_client.region = "cn-north-4"

            result = iam_user_access_key_rotation_90_days().execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "rotated within 90 days" in result[0].status_extended

    def test_old_access_key_fails(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_user_access_key_rotation_90_days.iam_user_access_key_rotation_90_days.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_service import AccessKey
            from prowler.providers.huaweicloud.services.iam.iam_user_access_key_rotation_90_days.iam_user_access_key_rotation_90_days import (
                iam_user_access_key_rotation_90_days,
            )

            old = (datetime.now(timezone.utc) - timedelta(days=120)).strftime(
                "%Y-%m-%dT%H:%M:%S.000000Z"
            )
            iam_client.access_keys = [
                AccessKey(
                    access="AKIA999",
                    user_id="user-1",
                    status="active",
                    create_time=old,
                )
            ]
            iam_client.users = []
            iam_client.audited_account = "123456789012"
            iam_client.region = "cn-north-4"

            result = iam_user_access_key_rotation_90_days().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "not been rotated for" in result[0].status_extended

    def test_access_key_90_days_12_hours_fails(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_user_access_key_rotation_90_days.iam_user_access_key_rotation_90_days.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_service import AccessKey
            from prowler.providers.huaweicloud.services.iam.iam_user_access_key_rotation_90_days.iam_user_access_key_rotation_90_days import (
                iam_user_access_key_rotation_90_days,
            )

            boundary = (
                datetime.now(timezone.utc) - timedelta(days=90, hours=12)
            ).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
            iam_client.access_keys = [
                AccessKey(
                    access="AKIA_BOUNDARY",
                    user_id="user-1",
                    status="active",
                    create_time=boundary,
                )
            ]
            iam_client.users = []
            iam_client.audited_account = "123456789012"
            iam_client.region = "cn-north-4"

            result = iam_user_access_key_rotation_90_days().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
