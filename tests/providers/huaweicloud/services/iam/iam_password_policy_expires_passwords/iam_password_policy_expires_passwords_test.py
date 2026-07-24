from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestIamPasswordPolicyExpiresPasswords:
    def test_password_validity_period_set_passes(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_password_policy_expires_passwords.iam_password_policy_expires_passwords.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_password_policy_expires_passwords.iam_password_policy_expires_passwords import (
                iam_password_policy_expires_passwords,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                PasswordPolicy,
            )

            iam_client.password_policy = PasswordPolicy(
                password_validity_period=90,
            )
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_password_policy_expires_passwords()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "expire after 90 days" in result[0].status_extended

    def test_password_validity_period_zero_fails(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_password_policy_expires_passwords.iam_password_policy_expires_passwords.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_password_policy_expires_passwords.iam_password_policy_expires_passwords import (
                iam_password_policy_expires_passwords,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                PasswordPolicy,
            )

            iam_client.password_policy = PasswordPolicy(
                password_validity_period=0,
            )
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_password_policy_expires_passwords()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not require passwords to expire" in result[0].status_extended

    def test_no_password_policy(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_password_policy_expires_passwords.iam_password_policy_expires_passwords.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_password_policy_expires_passwords.iam_password_policy_expires_passwords import (
                iam_password_policy_expires_passwords,
            )

            iam_client.password_policy = None
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_password_policy_expires_passwords()
            result = check.execute()

            assert len(result) == 0
