from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    ALIBABACLOUD_REGION,
    set_mocked_alibabacloud_provider,
)


class Test_ram_inactive_users_disabled:
    def test_no_users(self):
        ram_client = mock.MagicMock
        ram_client.users = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ram.ram_inactive_users_disabled.ram_inactive_users_disabled.ram_client",
            new=ram_client,
        ):
            from prowler.providers.alibabacloud.services.ram.ram_inactive_users_disabled.ram_inactive_users_disabled import (
                ram_inactive_users_disabled,
            )

            check = ram_inactive_users_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_ram_inactive_users_disabled_pass(self):
        ram_client = mock.MagicMock
        user_id = "test-user-123"
        user_arn = f"acs:ram::{ALIBABACLOUD_ACCOUNT_ID}:user/{user_id}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ram.ram_inactive_users_disabled.ram_inactive_users_disabled.ram_client",
            new=ram_client,
        ):
            from prowler.providers.alibabacloud.services.ram.ram_inactive_users_disabled.ram_inactive_users_disabled import (
                ram_inactive_users_disabled,
            )
            from prowler.providers.alibabacloud.services.ram.ram_service import User

            ram_client.users = {
                user_arn: User(
                    id=user_id,
                    name="test-user",
                    arn=user_arn,
                    console_login_enabled=True,
                    last_login_date="2024-12-01",
                )
            }
            ram_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = ram_inactive_users_disabled()
            result = check.execute()

            assert len(result) >= 1
            assert any(r.status == "PASS" for r in result)

    def test_ram_inactive_users_disabled_fail(self):
        ram_client = mock.MagicMock
        user_id = "test-user-456"
        user_arn = f"acs:ram::{ALIBABACLOUD_ACCOUNT_ID}:user/{user_id}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ram.ram_inactive_users_disabled.ram_inactive_users_disabled.ram_client",
            new=ram_client,
        ):
            from prowler.providers.alibabacloud.services.ram.ram_inactive_users_disabled.ram_inactive_users_disabled import (
                ram_inactive_users_disabled,
            )
            from prowler.providers.alibabacloud.services.ram.ram_service import User

            ram_client.users = {
                user_arn: User(
                    id=user_id,
                    name="test-user",
                    arn=user_arn,
                    console_login_enabled=True,
                    last_login_date="2023-01-01",
                )
            }
            ram_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = ram_inactive_users_disabled()
            result = check.execute()

            assert len(result) >= 1
            assert any(r.status == "FAIL" for r in result)
