from datetime import datetime, timedelta, timezone
from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestRamRotateAccessKey90Days:
    def test_old_access_key_fails(self):
        ram_client = mock.MagicMock()
        ram_client.audited_account = "1234567890"
        ram_client.region = "cn-hangzhou"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ram.ram_rotate_access_key_90_days.ram_rotate_access_key_90_days.ram_client",
                new=ram_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ram.ram_rotate_access_key_90_days.ram_rotate_access_key_90_days import (
                ram_rotate_access_key_90_days,
            )
            from prowler.providers.alibabacloud.services.ram.ram_service import (
                AccessKey,
                User,
            )

            access_key = AccessKey(
                access_key_id="AK1",
                status="Active",
                create_date=datetime.now(timezone.utc) - timedelta(days=120),
            )
            user = User(
                name="user1",
                user_id="u1",
                access_keys=[access_key],
            )
            ram_client.users = [user]

            check = ram_rotate_access_key_90_days()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_recent_access_key_passes(self):
        ram_client = mock.MagicMock()
        ram_client.audited_account = "1234567890"
        ram_client.region = "cn-hangzhou"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ram.ram_rotate_access_key_90_days.ram_rotate_access_key_90_days.ram_client",
                new=ram_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ram.ram_rotate_access_key_90_days.ram_rotate_access_key_90_days import (
                ram_rotate_access_key_90_days,
            )
            from prowler.providers.alibabacloud.services.ram.ram_service import (
                AccessKey,
                User,
            )

            access_key = AccessKey(
                access_key_id="AK2",
                status="Active",
                create_date=datetime.now(timezone.utc) - timedelta(days=10),
            )
            user = User(
                name="user2",
                user_id="u2",
                access_keys=[access_key],
            )
            ram_client.users = [user]

            check = ram_rotate_access_key_90_days()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
