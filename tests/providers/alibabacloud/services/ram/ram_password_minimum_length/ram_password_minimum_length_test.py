from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    set_mocked_alibabacloud_provider,
)


class Test_ram_password_minimum_length:
    def test_no_password_policy(self):
        ram_client = mock.MagicMock
        ram_client.account_id = ALIBABACLOUD_ACCOUNT_ID
        ram_client.password_policy = None

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ram.ram_password_minimum_length.ram_password_minimum_length.ram_client",
            new=ram_client,
        ):
            from prowler.providers.alibabacloud.services.ram.ram_password_minimum_length.ram_password_minimum_length import (
                ram_password_minimum_length,
            )

            check = ram_password_minimum_length()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "password-policy"
            assert result[0].account_uid == ALIBABACLOUD_ACCOUNT_ID
            assert result[0].region == "global"

    def test_password_policy_pass(self):
        ram_client = mock.MagicMock
        ram_client.account_id = ALIBABACLOUD_ACCOUNT_ID

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ram.ram_password_minimum_length.ram_password_minimum_length.ram_client",
            new=ram_client,
        ):
            from prowler.providers.alibabacloud.services.ram.ram_password_minimum_length.ram_password_minimum_length import (
                ram_password_minimum_length,
            )
            from prowler.providers.alibabacloud.services.ram.ram_service import PasswordPolicy

            ram_client.password_policy = PasswordPolicy(
                minimum_length=14,
            )

            check = ram_password_minimum_length()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "password-policy"
            assert "14+" in result[0].status_extended.lower()

    def test_password_policy_fail(self):
        ram_client = mock.MagicMock
        ram_client.account_id = ALIBABACLOUD_ACCOUNT_ID

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ram.ram_password_minimum_length.ram_password_minimum_length.ram_client",
            new=ram_client,
        ):
            from prowler.providers.alibabacloud.services.ram.ram_password_minimum_length.ram_password_minimum_length import (
                ram_password_minimum_length,
            )
            from prowler.providers.alibabacloud.services.ram.ram_service import PasswordPolicy

            ram_client.password_policy = PasswordPolicy(
                minimum_length=8,
            )

            check = ram_password_minimum_length()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "password-policy"
