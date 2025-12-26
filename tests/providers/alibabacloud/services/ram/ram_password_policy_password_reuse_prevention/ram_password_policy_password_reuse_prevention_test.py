from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestRamPasswordPolicyPasswordReusePrevention:
    def test_reuse_prevention_too_low_fails(self):
        ram_client = mock.MagicMock()
        ram_client.audited_account = "1234567890"
        ram_client.region = "cn-hangzhou"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ram.ram_password_policy_password_reuse_prevention.ram_password_policy_password_reuse_prevention.ram_client",
                new=ram_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ram.ram_password_policy_password_reuse_prevention.ram_password_policy_password_reuse_prevention import (
                ram_password_policy_password_reuse_prevention,
            )
            from prowler.providers.alibabacloud.services.ram.ram_service import (
                PasswordPolicy,
            )

            ram_client.password_policy = PasswordPolicy(password_reuse_prevention=0)

            check = ram_password_policy_password_reuse_prevention()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_reuse_prevention_set_passes(self):
        ram_client = mock.MagicMock()
        ram_client.audited_account = "1234567890"
        ram_client.region = "cn-hangzhou"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ram.ram_password_policy_password_reuse_prevention.ram_password_policy_password_reuse_prevention.ram_client",
                new=ram_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ram.ram_password_policy_password_reuse_prevention.ram_password_policy_password_reuse_prevention import (
                ram_password_policy_password_reuse_prevention,
            )
            from prowler.providers.alibabacloud.services.ram.ram_service import (
                PasswordPolicy,
            )

            ram_client.password_policy = PasswordPolicy(password_reuse_prevention=5)

            check = ram_password_policy_password_reuse_prevention()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
