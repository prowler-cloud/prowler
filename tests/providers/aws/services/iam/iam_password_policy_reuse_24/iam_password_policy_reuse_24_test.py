from unittest import mock

from boto3 import client, session
from moto import mock_iam

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_iam_password_policy_reuse_24:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=["us-east-1", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
        )

        return audit_info

    @mock_iam
    def test_iam_password_policy_reuse_prevention_equal_24(self):
        iam_client = client("iam")
        # update password policy
        iam_client.update_account_password_policy(PasswordReusePrevention=24)

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
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

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
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
