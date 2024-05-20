from re import search
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_iam_password_policy_symbol:
    from tests.providers.aws.utils import (
        AWS_ACCOUNT_ARN,
        AWS_ACCOUNT_NUMBER,
        AWS_REGION_US_EAST_1,
        set_mocked_aws_provider,
    )

    @mock_aws
    def test_iam_password_policy_no_symbol_flag(self):
        iam_client = client("iam")
        # update password policy
        iam_client.update_account_password_policy(RequireSymbols=False)

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_password_policy_symbol.iam_password_policy_symbol.iam_client",
            new=IAM(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_password_policy_symbol.iam_password_policy_symbol import (
                iam_password_policy_symbol,
            )

            check = iam_password_policy_symbol()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "IAM password policy does not require at least one symbol.",
                result[0].status_extended,
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:iam:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:password-policy"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_iam_password_policy_symbol_flag(self):
        iam_client = client("iam")
        # update password policy
        iam_client.update_account_password_policy(RequireSymbols=True)

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_password_policy_symbol.iam_password_policy_symbol.iam_client",
            new=IAM(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_password_policy_symbol.iam_password_policy_symbol import (
                iam_password_policy_symbol,
            )

            check = iam_password_policy_symbol()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "IAM password policy requires at least one symbol.",
                result[0].status_extended,
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:iam:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:password-policy"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_access_denied(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_password_policy_symbol.iam_password_policy_symbol.iam_client",
                new=IAM(aws_provider),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_password_policy_symbol.iam_password_policy_symbol import (
                    iam_password_policy_symbol,
                )

                service_client.password_policy = None
                check = iam_password_policy_symbol()
                result = check.execute()
                assert len(result) == 0
