from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestIamPasswordPolicyMaxConsecutiveIdenticalChars:
    def test_max_consecutive_3_passes(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_password_policy_max_consecutive_identical_chars.iam_password_policy_max_consecutive_identical_chars.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_password_policy_max_consecutive_identical_chars.iam_password_policy_max_consecutive_identical_chars import (
                iam_password_policy_max_consecutive_identical_chars,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                PasswordPolicy,
            )

            iam_client.password_policy = PasswordPolicy(
                maximum_consecutive_identical_chars=3,
            )
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_password_policy_max_consecutive_identical_chars()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "limits consecutive identical characters" in result[0].status_extended
            )

    def test_max_consecutive_0_fails(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_password_policy_max_consecutive_identical_chars.iam_password_policy_max_consecutive_identical_chars.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_password_policy_max_consecutive_identical_chars.iam_password_policy_max_consecutive_identical_chars import (
                iam_password_policy_max_consecutive_identical_chars,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                PasswordPolicy,
            )

            iam_client.password_policy = PasswordPolicy(
                maximum_consecutive_identical_chars=0,
            )
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_password_policy_max_consecutive_identical_chars()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not limit" in result[0].status_extended

    def test_no_password_policy(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_password_policy_max_consecutive_identical_chars.iam_password_policy_max_consecutive_identical_chars.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_password_policy_max_consecutive_identical_chars.iam_password_policy_max_consecutive_identical_chars import (
                iam_password_policy_max_consecutive_identical_chars,
            )

            iam_client.password_policy = None
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_password_policy_max_consecutive_identical_chars()
            result = check.execute()

            assert len(result) == 0
