from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestRamPasswordPolicyUppercase:
    def test_uppercase_not_required_fails(self):
        ram_client = mock.MagicMock()
        ram_client.audited_account = "1234567890"
        ram_client.region = "cn-hangzhou"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ram.ram_password_policy_uppercase.ram_password_policy_uppercase.ram_client",
                new=ram_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ram.ram_password_policy_uppercase.ram_password_policy_uppercase import (
                ram_password_policy_uppercase,
            )
            from prowler.providers.alibabacloud.services.ram.ram_service import (
                PasswordPolicy,
            )

            ram_client.password_policy = PasswordPolicy(
                require_uppercase_characters=False
            )

            check = ram_password_policy_uppercase()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_uppercase_required_passes(self):
        ram_client = mock.MagicMock()
        ram_client.audited_account = "1234567890"
        ram_client.region = "cn-hangzhou"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ram.ram_password_policy_uppercase.ram_password_policy_uppercase.ram_client",
                new=ram_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ram.ram_password_policy_uppercase.ram_password_policy_uppercase import (
                ram_password_policy_uppercase,
            )
            from prowler.providers.alibabacloud.services.ram.ram_service import (
                PasswordPolicy,
            )

            ram_client.password_policy = PasswordPolicy(
                require_uppercase_characters=True
            )

            check = ram_password_policy_uppercase()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
