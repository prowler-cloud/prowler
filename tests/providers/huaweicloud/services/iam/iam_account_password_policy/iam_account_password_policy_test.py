from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestIamAccountPasswordPolicy:
    def test_password_policy_min_length_14_passes(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_account_password_policy.iam_account_password_policy.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_account_password_policy.iam_account_password_policy import (
                iam_account_password_policy,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                PasswordPolicy,
            )

            iam_client.password_policy = PasswordPolicy(minimum_password_length=14)
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_account_password_policy()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "14" in result[0].status_extended

    def test_password_policy_min_length_8_fails(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_account_password_policy.iam_account_password_policy.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_account_password_policy.iam_account_password_policy import (
                iam_account_password_policy,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                PasswordPolicy,
            )

            iam_client.password_policy = PasswordPolicy(minimum_password_length=8)
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_account_password_policy()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "8" in result[0].status_extended
            assert "14" in result[0].status_extended

    def test_no_password_policy(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_account_password_policy.iam_account_password_policy.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_account_password_policy.iam_account_password_policy import (
                iam_account_password_policy,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                PasswordPolicy,
            )

            iam_client.password_policy = PasswordPolicy()
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_account_password_policy()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
