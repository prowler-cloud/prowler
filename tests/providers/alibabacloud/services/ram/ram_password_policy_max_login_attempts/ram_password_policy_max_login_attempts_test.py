from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestRamPasswordPolicyMaxLoginAttempts:
    def test_max_login_attempts_zero_fails(self):
        ram_client = mock.MagicMock()
        ram_client.audited_account = "1234567890"
        ram_client.region = "cn-hangzhou"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ram.ram_password_policy_max_login_attempts.ram_password_policy_max_login_attempts.ram_client",
                new=ram_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ram.ram_password_policy_max_login_attempts.ram_password_policy_max_login_attempts import (
                ram_password_policy_max_login_attempts,
            )
            from prowler.providers.alibabacloud.services.ram.ram_service import (
                PasswordPolicy,
            )

            ram_client.password_policy = PasswordPolicy(max_login_attempts=0)

            check = ram_password_policy_max_login_attempts()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_max_login_attempts_within_or_above_limit_passes(self):
        ram_client = mock.MagicMock()
        ram_client.audited_account = "1234567890"
        ram_client.region = "cn-hangzhou"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ram.ram_password_policy_max_login_attempts.ram_password_policy_max_login_attempts.ram_client",
                new=ram_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ram.ram_password_policy_max_login_attempts.ram_password_policy_max_login_attempts import (
                ram_password_policy_max_login_attempts,
            )
            from prowler.providers.alibabacloud.services.ram.ram_service import (
                PasswordPolicy,
            )

            ram_client.password_policy = PasswordPolicy(max_login_attempts=5)

            check = ram_password_policy_max_login_attempts()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
