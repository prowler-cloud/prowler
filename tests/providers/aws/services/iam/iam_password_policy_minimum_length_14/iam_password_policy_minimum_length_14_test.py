from re import search
from unittest import mock

from boto3 import client
from moto import mock_iam

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"


class Test_iam_password_policy_minimum_length_14:
    @mock_iam
    def test_iam_password_policy_minimum_length_equal_14(self):
        iam_client = client("iam")
        # update password policy
        iam_client.update_account_password_policy(MinimumPasswordLength=14)

        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_password_policy_minimum_length_14.iam_password_policy_minimum_length_14.iam_client",
            new=IAM(current_audit_info),
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
            assert result[0].resource_arn == AWS_ACCOUNT_ARN
            assert result[0].region == AWS_REGION

    @mock_iam
    def test_iam_password_policy_minimum_length_greater_14(self):
        iam_client = client("iam")
        # update password policy
        iam_client.update_account_password_policy(MinimumPasswordLength=20)

        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_password_policy_minimum_length_14.iam_password_policy_minimum_length_14.iam_client",
            new=IAM(current_audit_info),
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
            assert result[0].resource_arn == AWS_ACCOUNT_ARN
            assert result[0].region == AWS_REGION

    @mock_iam
    def test_iam_password_policy_minimum_length_less_14(self):
        iam_client = client("iam")
        # update password policy
        iam_client.update_account_password_policy(MinimumPasswordLength=10)

        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_password_policy_minimum_length_14.iam_password_policy_minimum_length_14.iam_client",
            new=IAM(current_audit_info),
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
            assert result[0].resource_arn == AWS_ACCOUNT_ARN
            assert result[0].region == AWS_REGION
