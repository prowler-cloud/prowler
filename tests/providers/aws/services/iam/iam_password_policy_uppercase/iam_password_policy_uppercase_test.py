from unittest import mock

from boto3 import client
from moto import mock_iam

from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"


class Test_iam_password_policy_uppercase:
    @mock_iam
    def test_iam_password_policy_no_uppercase_flag(self):
        iam_client = client("iam")
        # update password policy
        iam_client.update_account_password_policy(RequireUppercaseCharacters=False)

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_password_policy_uppercase.iam_password_policy_uppercase.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_password_policy_uppercase.iam_password_policy_uppercase import (
                iam_password_policy_uppercase,
            )

            check = iam_password_policy_uppercase()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "IAM password policy does not require at least one uppercase letter."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == AWS_ACCOUNT_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_iam
    def test_iam_password_policy_uppercase_flag(self):
        iam_client = client("iam")
        # update password policy
        iam_client.update_account_password_policy(RequireUppercaseCharacters=True)

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_password_policy_uppercase.iam_password_policy_uppercase.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_password_policy_uppercase.iam_password_policy_uppercase import (
                iam_password_policy_uppercase,
            )

            check = iam_password_policy_uppercase()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "IAM password policy requires at least one uppercase letter."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == AWS_ACCOUNT_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1
