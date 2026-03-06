from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestRamPasswordPolicySymbol:
    def test_symbols_not_required_fails(self):
        ram_client = mock.MagicMock()
        ram_client.audited_account = "1234567890"
        ram_client.region = "cn-hangzhou"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ram.ram_password_policy_symbol.ram_password_policy_symbol.ram_client",
                new=ram_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ram.ram_password_policy_symbol.ram_password_policy_symbol import (
                ram_password_policy_symbol,
            )
            from prowler.providers.alibabacloud.services.ram.ram_service import (
                PasswordPolicy,
            )

            ram_client.password_policy = PasswordPolicy(require_symbols=False)

            check = ram_password_policy_symbol()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_symbols_required_passes(self):
        ram_client = mock.MagicMock()
        ram_client.audited_account = "1234567890"
        ram_client.region = "cn-hangzhou"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ram.ram_password_policy_symbol.ram_password_policy_symbol.ram_client",
                new=ram_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ram.ram_password_policy_symbol.ram_password_policy_symbol import (
                ram_password_policy_symbol,
            )
            from prowler.providers.alibabacloud.services.ram.ram_service import (
                PasswordPolicy,
            )

            ram_client.password_policy = PasswordPolicy(require_symbols=True)

            check = ram_password_policy_symbol()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
