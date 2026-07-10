from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestIamPasswordPolicyReusePrevention:
    def test_reuse_prevention_3_passes(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_password_policy_reuse_prevention.iam_password_policy_reuse_prevention.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_password_policy_reuse_prevention.iam_password_policy_reuse_prevention import (
                iam_password_policy_reuse_prevention,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                PasswordPolicy,
            )

            iam_client.password_policy = PasswordPolicy(
                number_of_recent_passwords_disallowed=3,
            )
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_password_policy_reuse_prevention()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "disallows reuse of the last 3 passwords" in result[0].status_extended

    def test_reuse_prevention_1_fails(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_password_policy_reuse_prevention.iam_password_policy_reuse_prevention.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_password_policy_reuse_prevention.iam_password_policy_reuse_prevention import (
                iam_password_policy_reuse_prevention,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                PasswordPolicy,
            )

            iam_client.password_policy = PasswordPolicy(
                number_of_recent_passwords_disallowed=1,
            )
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_password_policy_reuse_prevention()
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
                "prowler.providers.huaweicloud.services.iam.iam_password_policy_reuse_prevention.iam_password_policy_reuse_prevention.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_password_policy_reuse_prevention.iam_password_policy_reuse_prevention import (
                iam_password_policy_reuse_prevention,
            )

            iam_client.password_policy = None
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_password_policy_reuse_prevention()
            result = check.execute()

            assert len(result) == 0
