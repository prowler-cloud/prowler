from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.iam.iam_service import PasswordPolicy
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_iam_password_policy_reuse_24_fixer:
    @mock_aws
    def test_iam_password_policy_reuse_24_fixer(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_password_policy_reuse_24.iam_password_policy_reuse_24_fixer.iam_client",
                new=IAM(aws_provider),
            ) as service_client,
        ):
            service_client.password_policy = PasswordPolicy(
                length=10,
                symbols=True,
                numbers=True,
                uppercase=True,
                lowercase=True,
                allow_change=True,
                expiration=True,
                max_age=40,
                reuse_prevention=2,
                hard_expiry=True,
            )
            from prowler.providers.aws.services.iam.iam_password_policy_reuse_24.iam_password_policy_reuse_24_fixer import (
                fixer,
            )

            assert fixer(resource_id=AWS_ACCOUNT_NUMBER)

    @mock_aws
    def test_iam_password_policy_reuse_24_fixer_without_optional_settings(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_password_policy_reuse_24.iam_password_policy_reuse_24_fixer.iam_client",
                new=IAM(aws_provider),
            ) as service_client,
        ):
            # IAM default password policy, used when the account has no password policy
            service_client.password_policy = PasswordPolicy(
                length=8,
                symbols=False,
                numbers=False,
                uppercase=False,
                lowercase=False,
                allow_change=True,
                expiration=False,
                max_age=None,
                reuse_prevention=None,
                hard_expiry=None,
            )
            from prowler.providers.aws.services.iam.iam_password_policy_reuse_24.iam_password_policy_reuse_24_fixer import (
                fixer,
            )

            assert fixer(resource_id=AWS_ACCOUNT_NUMBER)

            password_policy = client("iam").get_account_password_policy()[
                "PasswordPolicy"
            ]
            assert password_policy["PasswordReusePrevention"] == 24

    @mock_aws
    def test_iam_password_policy_reuse_24_fixer_with_disabled_optional_settings(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_password_policy_reuse_24.iam_password_policy_reuse_24_fixer.iam_client",
                new=IAM(aws_provider),
            ) as service_client,
        ):
            # Password expiration and reuse prevention disabled are reported as 0
            service_client.password_policy = PasswordPolicy(
                length=8,
                symbols=False,
                numbers=False,
                uppercase=False,
                lowercase=False,
                allow_change=True,
                expiration=False,
                max_age=0,
                reuse_prevention=0,
                hard_expiry=False,
            )
            from prowler.providers.aws.services.iam.iam_password_policy_reuse_24.iam_password_policy_reuse_24_fixer import (
                fixer,
            )

            assert fixer(resource_id=AWS_ACCOUNT_NUMBER)

            password_policy = client("iam").get_account_password_policy()[
                "PasswordPolicy"
            ]
            assert password_policy["PasswordReusePrevention"] == 24
