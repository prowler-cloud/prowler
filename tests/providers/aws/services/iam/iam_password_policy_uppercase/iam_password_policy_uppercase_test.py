from unittest import mock

from boto3 import client
from moto import mock_iam


class Test_iam_password_policy_uppercase:
    @mock_iam
    def test_iam_password_policy_no_uppercase_flag(self):
        iam_client = client("iam")
        # update password policy
        iam_client.update_account_password_policy(RequireUppercaseCharacters=False)

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_password_policy_uppercase.iam_password_policy_uppercase.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_password_policy_uppercase.iam_password_policy_uppercase import (
                iam_password_policy_uppercase,
            )

            check = iam_password_policy_uppercase()
            result = check.execute()
            assert result[0].status == "FAIL"

    @mock_iam
    def test_iam_password_policy_uppercase_flag(self):
        iam_client = client("iam")
        # update password policy
        iam_client.update_account_password_policy(RequireUppercaseCharacters=True)

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_password_policy_uppercase.iam_password_policy_uppercase.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_password_policy_uppercase.iam_password_policy_uppercase import (
                iam_password_policy_uppercase,
            )

            check = iam_password_policy_uppercase()
            result = check.execute()
            assert result[0].status == "PASS"
