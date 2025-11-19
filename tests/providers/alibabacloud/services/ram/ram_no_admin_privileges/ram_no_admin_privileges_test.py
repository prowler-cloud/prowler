from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    ALIBABACLOUD_REGION,
    set_mocked_alibabacloud_provider,
)


class Test_ram_no_admin_privileges:
    def test_no_users(self):
        ram_client = mock.MagicMock
        ram_client.users = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ram.ram_no_admin_privileges.ram_no_admin_privileges.ram_client",
            new=ram_client,
        ):
            from prowler.providers.alibabacloud.services.ram.ram_no_admin_privileges.ram_no_admin_privileges import (
                ram_no_admin_privileges,
            )

            check = ram_no_admin_privileges()
            result = check.execute()
            assert len(result) == 0

    def test_ram_no_admin_privileges_pass(self):
        ram_client = mock.MagicMock
        user_id = "test-user-123"
        user_arn = f"acs:ram::{ALIBABACLOUD_ACCOUNT_ID}:user/{user_id}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ram.ram_no_admin_privileges.ram_no_admin_privileges.ram_client",
            new=ram_client,
        ):
            from prowler.providers.alibabacloud.services.ram.ram_no_admin_privileges.ram_no_admin_privileges import (
                ram_no_admin_privileges,
            )
            from prowler.providers.alibabacloud.services.ram.ram_service import User

            ram_client.users = {
                user_arn: User(
                    id=user_id,
                    name="test-user",
                    arn=user_arn,
                    console_login_enabled=True,
                    attached_policies=[],
                )
            }
            ram_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = ram_no_admin_privileges()
            result = check.execute()

            assert len(result) >= 1
            assert any(r.status == "PASS" for r in result)

    def test_ram_no_admin_privileges_fail(self):
        ram_client = mock.MagicMock
        user_id = "test-user-456"
        user_arn = f"acs:ram::{ALIBABACLOUD_ACCOUNT_ID}:user/{user_id}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ram.ram_no_admin_privileges.ram_no_admin_privileges.ram_client",
            new=ram_client,
        ):
            from prowler.providers.alibabacloud.services.ram.ram_no_admin_privileges.ram_no_admin_privileges import (
                ram_no_admin_privileges,
            )
            from prowler.providers.alibabacloud.services.ram.ram_service import User

            ram_client.users = {
                user_arn: User(
                    id=user_id,
                    name="test-user",
                    arn=user_arn,
                    console_login_enabled=True,
                    attached_policies=[{"PolicyName": "AdministratorAccess", "PolicyType": "System"}],
                )
            }
            ram_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = ram_no_admin_privileges()
            result = check.execute()

            assert len(result) >= 1
            assert any(r.status == "FAIL" for r in result)
