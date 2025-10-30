from unittest import mock
from datetime import datetime, timedelta

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    set_mocked_alibabacloud_provider,
)


class Test_ram_access_key_rotation:
    def test_no_users(self):
        ram_client = mock.MagicMock
        ram_client.users = {{}}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ram.ram_access_key_rotation.ram_access_key_rotation.ram_client",
            new=ram_client,
        ):
            from prowler.providers.alibabacloud.services.ram.ram_access_key_rotation.ram_access_key_rotation import (
                ram_access_key_rotation,
            )

            check = ram_access_key_rotation()
            result = check.execute()
            assert len(result) == 0

    def test_access_key_rotated_recently(self):
        ram_client = mock.MagicMock
        user_id = "test-user-123"
        user_arn = f"acs:ram::{{ALIBABACLOUD_ACCOUNT_ID}}:user/{{user_id}}"
        recent_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ram.ram_access_key_rotation.ram_access_key_rotation.ram_client",
            new=ram_client,
        ):
            from prowler.providers.alibabacloud.services.ram.ram_access_key_rotation.ram_access_key_rotation import (
                ram_access_key_rotation,
            )
            from prowler.providers.alibabacloud.services.ram.ram_service import User, AccessKey

            ram_client.users = {{
                user_arn: User(
                    id=user_id,
                    name="test-user",
                    arn=user_arn,
                    access_keys=[
                        AccessKey(
                            access_key_id="LTAI_test",
                            user_name="test-user",
                            status="Active",
                            create_date=recent_date,
                        )
                    ],
                )
            }}
            ram_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = ram_access_key_rotation()
            result = check.execute()

            assert len(result) >= 1
            assert any(r.status == "PASS" for r in result)

    def test_access_key_not_rotated(self):
        ram_client = mock.MagicMock
        user_id = "test-user-456"
        user_arn = f"acs:ram::{{ALIBABACLOUD_ACCOUNT_ID}}:user/{{user_id}}"
        old_date = (datetime.now() - timedelta(days=120)).strftime("%Y-%m-%d")

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ram.ram_access_key_rotation.ram_access_key_rotation.ram_client",
            new=ram_client,
        ):
            from prowler.providers.alibabacloud.services.ram.ram_access_key_rotation.ram_access_key_rotation import (
                ram_access_key_rotation,
            )
            from prowler.providers.alibabacloud.services.ram.ram_service import User, AccessKey

            ram_client.users = {{
                user_arn: User(
                    id=user_id,
                    name="test-user",
                    arn=user_arn,
                    access_keys=[
                        AccessKey(
                            access_key_id="LTAI_old",
                            user_name="test-user",
                            status="Active",
                            create_date=old_date,
                        )
                    ],
                )
            }}
            ram_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = ram_access_key_rotation()
            result = check.execute()

            assert len(result) >= 1
            assert any(r.status == "FAIL" for r in result)
