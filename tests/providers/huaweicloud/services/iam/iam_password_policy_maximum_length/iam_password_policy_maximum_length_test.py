from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestIamPasswordPolicyMaximumLength:
    def test_maximum_length_32_passes(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_password_policy_maximum_length.iam_password_policy_maximum_length.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_password_policy_maximum_length.iam_password_policy_maximum_length import (
                iam_password_policy_maximum_length,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                PasswordPolicy,
            )

            iam_client.password_policy = PasswordPolicy(
                maximum_password_length=32,
            )
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_password_policy_maximum_length()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "32 characters" in result[0].status_extended

    def test_maximum_length_below_32_fails(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_password_policy_maximum_length.iam_password_policy_maximum_length.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_password_policy_maximum_length.iam_password_policy_maximum_length import (
                iam_password_policy_maximum_length,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                PasswordPolicy,
            )

            iam_client.password_policy = PasswordPolicy(
                maximum_password_length=16,
            )
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_password_policy_maximum_length()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "less than the recommended 32" in result[0].status_extended

    def test_no_password_policy(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_password_policy_maximum_length.iam_password_policy_maximum_length.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_password_policy_maximum_length.iam_password_policy_maximum_length import (
                iam_password_policy_maximum_length,
            )

            iam_client.password_policy = None
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_password_policy_maximum_length()
            result = check.execute()

            assert len(result) == 0
