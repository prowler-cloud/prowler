from re import search
from unittest import mock

from boto3 import session
from moto import mock_iam

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


class Test_iam_password_policy_expires_passwords_within_90_days_or_less:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
                region_name=AWS_REGION,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=AWS_REGION,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
        )
        return audit_info

    @mock_iam
    def test_password_expiration_lower_90(self):
        from prowler.providers.aws.services.iam.iam_service import IAM, PasswordPolicy

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_password_policy_expires_passwords_within_90_days_or_less.iam_password_policy_expires_passwords_within_90_days_or_less.iam_client",
                new=IAM(audit_info),
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
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert search(
                    "Password expiration is set lower than 90 days",
                    result[0].status_extended,
                )

    @mock_iam
    def test_password_expiration_greater_90(self):
        from prowler.providers.aws.services.iam.iam_service import IAM, PasswordPolicy

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_password_policy_expires_passwords_within_90_days_or_less.iam_password_policy_expires_passwords_within_90_days_or_less.iam_client",
                new=IAM(audit_info),
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
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert search(
                    "Password expiration is set greater than 90 days",
                    result[0].status_extended,
                )

    @mock_iam
    def test_password_expiration_just_90(self):
        from prowler.providers.aws.services.iam.iam_service import IAM, PasswordPolicy

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_password_policy_expires_passwords_within_90_days_or_less.iam_password_policy_expires_passwords_within_90_days_or_less.iam_client",
                new=IAM(audit_info),
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
                    max_age=90,
                    reuse_prevention=2,
                    hard_expiry=True,
                )
                check = iam_password_policy_expires_passwords_within_90_days_or_less()
                result = check.execute()
                assert result[0].status == "PASS"
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert search(
                    "Password expiration is set lower than 90 days",
                    result[0].status_extended,
                )
