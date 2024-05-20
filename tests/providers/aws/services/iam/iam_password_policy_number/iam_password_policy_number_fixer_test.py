from unittest import mock

from moto import mock_aws

from prowler.providers.aws.services.iam.iam_service import PasswordPolicy
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_iam_password_policy_number_fixer:
    @mock_aws
    def test_iam_password_policy_number_fixer(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_password_policy_number.iam_password_policy_number_fixer.iam_client",
            new=IAM(aws_provider),
        ) as service_client:
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
            from prowler.providers.aws.services.iam.iam_password_policy_number.iam_password_policy_number_fixer import (
                fixer,
            )

            assert fixer(resource_id=AWS_ACCOUNT_NUMBER)
