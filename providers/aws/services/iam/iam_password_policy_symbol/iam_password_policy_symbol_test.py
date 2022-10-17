from unittest import mock

from boto3 import client
from moto import mock_iam


class Test_iam_password_policy_symbol:
    @mock_iam
    def test_iam_password_policy_no_symbol_flag(self):
        iam_client = client("iam")
        # update password policy
        iam_client.update_account_password_policy(RequireSymbols=False)

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "providers.aws.services.iam.iam_password_policy_symbol.iam_password_policy_symbol.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.iam.iam_password_policy_symbol.iam_password_policy_symbol import (
                iam_password_policy_symbol,
            )

            check = iam_password_policy_symbol()
            result = check.execute()
            assert result[0].status == "FAIL"

    @mock_iam
    def test_iam_password_policy_symbol_flag(self):
        iam_client = client("iam")
        # update password policy
        iam_client.update_account_password_policy(RequireSymbols=True)

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "providers.aws.services.iam.iam_password_policy_symbol.iam_password_policy_symbol.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.iam.iam_password_policy_symbol.iam_password_policy_symbol import (
                iam_password_policy_symbol,
            )

            check = iam_password_policy_symbol()
            result = check.execute()
            assert result[0].status == "PASS"
