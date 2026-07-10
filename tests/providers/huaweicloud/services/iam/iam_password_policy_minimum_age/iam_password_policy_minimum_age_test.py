from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestIamPasswordPolicyMinimumAge:
    def test_minimum_age_set_passes(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_password_policy_minimum_age.iam_password_policy_minimum_age.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_password_policy_minimum_age.iam_password_policy_minimum_age import (
                iam_password_policy_minimum_age,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                PasswordPolicy,
            )

            iam_client.password_policy = PasswordPolicy(
                minimum_password_age=2,
            )
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_password_policy_minimum_age()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "minimum password age of 2 days" in result[0].status_extended

    def test_minimum_age_zero_fails(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_password_policy_minimum_age.iam_password_policy_minimum_age.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_password_policy_minimum_age.iam_password_policy_minimum_age import (
                iam_password_policy_minimum_age,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                PasswordPolicy,
            )

            iam_client.password_policy = PasswordPolicy(
                minimum_password_age=0,
            )
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_password_policy_minimum_age()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not enforce a minimum password age" in result[0].status_extended

    def test_no_password_policy(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_password_policy_minimum_age.iam_password_policy_minimum_age.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_password_policy_minimum_age.iam_password_policy_minimum_age import (
                iam_password_policy_minimum_age,
            )

            iam_client.password_policy = None
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_password_policy_minimum_age()
            result = check.execute()

            assert len(result) == 0
