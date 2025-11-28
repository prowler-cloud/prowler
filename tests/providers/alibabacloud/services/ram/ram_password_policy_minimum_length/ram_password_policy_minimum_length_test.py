from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestRamPasswordPolicyMinimumLength:
    def test_policy_too_short_fails(self):
        ram_client = mock.MagicMock()
        ram_client.audited_account = "1234567890"
        ram_client.region = "cn-hangzhou"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ram.ram_password_policy_minimum_length.ram_password_policy_minimum_length.ram_client",
                new=ram_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ram.ram_password_policy_minimum_length.ram_password_policy_minimum_length import (
                ram_password_policy_minimum_length,
            )
            from prowler.providers.alibabacloud.services.ram.ram_service import (
                PasswordPolicy,
            )

            ram_client.password_policy = PasswordPolicy(minimum_password_length=8)

            check = ram_password_policy_minimum_length()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "less than the recommended 14 characters" in result[0].status_extended
            )

    def test_policy_long_enough_passes(self):
        ram_client = mock.MagicMock()
        ram_client.audited_account = "1234567890"
        ram_client.region = "cn-hangzhou"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ram.ram_password_policy_minimum_length.ram_password_policy_minimum_length.ram_client",
                new=ram_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ram.ram_password_policy_minimum_length.ram_password_policy_minimum_length import (
                ram_password_policy_minimum_length,
            )
            from prowler.providers.alibabacloud.services.ram.ram_service import (
                PasswordPolicy,
            )

            ram_client.password_policy = PasswordPolicy(minimum_password_length=14)

            check = ram_password_policy_minimum_length()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "minimum length of 14 characters" in result[0].status_extended
