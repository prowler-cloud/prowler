from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestIamPasswordPolicyCharCombination:
    def test_char_combination_3_passes(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_password_policy_char_combination.iam_password_policy_char_combination.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_password_policy_char_combination.iam_password_policy_char_combination import (
                iam_password_policy_char_combination,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                PasswordPolicy,
            )

            iam_client.password_policy = PasswordPolicy(
                password_char_combination=3,
            )
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_password_policy_char_combination()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "at least 3 character types" in result[0].status_extended

    def test_char_combination_2_fails(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_password_policy_char_combination.iam_password_policy_char_combination.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_password_policy_char_combination.iam_password_policy_char_combination import (
                iam_password_policy_char_combination,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                PasswordPolicy,
            )

            iam_client.password_policy = PasswordPolicy(
                password_char_combination=2,
            )
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_password_policy_char_combination()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "less than the recommended 3" in result[0].status_extended

    def test_no_password_policy(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_password_policy_char_combination.iam_password_policy_char_combination.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_password_policy_char_combination.iam_password_policy_char_combination import (
                iam_password_policy_char_combination,
            )

            iam_client.password_policy = None
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_password_policy_char_combination()
            result = check.execute()

            assert len(result) == 0
