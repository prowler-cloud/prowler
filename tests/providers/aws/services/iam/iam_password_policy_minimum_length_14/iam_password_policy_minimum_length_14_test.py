from re import search
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_iam_password_policy_minimum_length_14:
    from tests.providers.aws.audit_info_utils import (
        AWS_ACCOUNT_ARN,
        AWS_ACCOUNT_NUMBER,
        AWS_REGION_US_EAST_1,
        set_mocked_aws_provider,
    )

    @mock_aws
    def test_iam_password_policy_minimum_length_equal_14(self):
        iam_client = client("iam")
        # update password policy
        iam_client.update_account_password_policy(MinimumPasswordLength=14)

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_password_policy_minimum_length_14.iam_password_policy_minimum_length_14.iam_client",
            new=IAM(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_password_policy_minimum_length_14.iam_password_policy_minimum_length_14 import (
                iam_password_policy_minimum_length_14,
            )

            check = iam_password_policy_minimum_length_14()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "IAM password policy requires minimum length of 14 characters.",
                result[0].status_extended,
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:iam:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:password-policy"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_iam_password_policy_minimum_length_greater_14(self):
        iam_client = client("iam")
        # update password policy
        iam_client.update_account_password_policy(MinimumPasswordLength=20)

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_password_policy_minimum_length_14.iam_password_policy_minimum_length_14.iam_client",
            new=IAM(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_password_policy_minimum_length_14.iam_password_policy_minimum_length_14 import (
                iam_password_policy_minimum_length_14,
            )

            check = iam_password_policy_minimum_length_14()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "IAM password policy requires minimum length of 14 characters.",
                result[0].status_extended,
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:iam:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:password-policy"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_iam_password_policy_minimum_length_less_14(self):
        iam_client = client("iam")
        # update password policy
        iam_client.update_account_password_policy(MinimumPasswordLength=10)

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_password_policy_minimum_length_14.iam_password_policy_minimum_length_14.iam_client",
            new=IAM(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_password_policy_minimum_length_14.iam_password_policy_minimum_length_14 import (
                iam_password_policy_minimum_length_14,
            )

            check = iam_password_policy_minimum_length_14()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "IAM password policy does not require minimum length of 14 characters.",
                result[0].status_extended,
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:iam:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:password-policy"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
