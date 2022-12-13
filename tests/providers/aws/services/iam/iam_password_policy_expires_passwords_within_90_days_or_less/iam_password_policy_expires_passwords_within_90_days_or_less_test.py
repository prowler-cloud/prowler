from re import search
from unittest import mock

from moto import mock_iam


class Test_iam_password_policy_expires_passwords_within_90_days_or_less:
    @mock_iam
    def test_password_expiration_lower_90(self):
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM, PasswordPolicy

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_password_policy_expires_passwords_within_90_days_or_less.iam_password_policy_expires_passwords_within_90_days_or_less.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_password_policy_expires_passwords_within_90_days_or_less.iam_password_policy_expires_passwords_within_90_days_or_less import (
                iam_password_policy_expires_passwords_within_90_days_or_less,
            )

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
            check = iam_password_policy_expires_passwords_within_90_days_or_less()
            result = check.execute()
            assert result[0].status == "PASS"
            assert result[0].resource_id == "password_policy"
            assert search(
                "Password expiration is set lower than 90 days",
                result[0].status_extended,
            )

    @mock_iam
    def test_password_expiration_greater_90(self):
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM, PasswordPolicy

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_password_policy_expires_passwords_within_90_days_or_less.iam_password_policy_expires_passwords_within_90_days_or_less.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_password_policy_expires_passwords_within_90_days_or_less.iam_password_policy_expires_passwords_within_90_days_or_less import (
                iam_password_policy_expires_passwords_within_90_days_or_less,
            )

            service_client.password_policy = PasswordPolicy(
                length=10,
                symbols=True,
                numbers=True,
                uppercase=True,
                lowercase=True,
                allow_change=True,
                expiration=True,
                max_age=100,
                reuse_prevention=2,
                hard_expiry=True,
            )
            check = iam_password_policy_expires_passwords_within_90_days_or_less()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "password_policy"
            assert search(
                "Password expiration is set greater than 90 days",
                result[0].status_extended,
            )
