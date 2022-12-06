from unittest import mock

from boto3 import client
from moto import mock_iam


class Test_iam_password_policy_reuse_24:
    @mock_iam
    def test_iam_password_policy_reuse_prevention_equal_24(self):
        iam_client = client("iam")
        # update password policy
        iam_client.update_account_password_policy(PasswordReusePrevention=24)

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_password_policy_reuse_24.iam_password_policy_reuse_24.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_password_policy_reuse_24.iam_password_policy_reuse_24 import (
                iam_password_policy_reuse_24,
            )

            check = iam_password_policy_reuse_24()
            result = check.execute()
            assert result[0].status == "PASS"

    @mock_iam
    def test_iam_password_policy_reuse_prevention_less_24(self):
        iam_client = client("iam")
        # update password policy
        iam_client.update_account_password_policy(PasswordReusePrevention=20)

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_password_policy_reuse_24.iam_password_policy_reuse_24.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_password_policy_reuse_24.iam_password_policy_reuse_24 import (
                iam_password_policy_reuse_24,
            )

            check = iam_password_policy_reuse_24()
            result = check.execute()
            assert result[0].status == "FAIL"
