from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_iam

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_iam_password_policy_lowercase:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
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
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )

        return audit_info

    @mock_iam
    def test_iam_password_policy_no_lowercase_flag(self):
        iam_client = client("iam")
        # update password policy
        iam_client.update_account_password_policy(RequireLowercaseCharacters=False)

        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_password_policy_lowercase.iam_password_policy_lowercase.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_password_policy_lowercase.iam_password_policy_lowercase import (
                iam_password_policy_lowercase,
            )

            check = iam_password_policy_lowercase()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert search(
                "IAM password policy does not require at least one lowercase letter.",
                result[0].status_extended,
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER

    @mock_iam
    def test_iam_password_policy_lowercase_flag(self):
        iam_client = client("iam")
        # update password policy
        iam_client.update_account_password_policy(RequireLowercaseCharacters=True)

        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_password_policy_lowercase.iam_password_policy_lowercase.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_password_policy_lowercase.iam_password_policy_lowercase import (
                iam_password_policy_lowercase,
            )

            check = iam_password_policy_lowercase()
            result = check.execute()
            assert result[0].status == "PASS"
            assert search(
                "IAM password policy requires at least one lowercase letter.",
                result[0].status_extended,
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
