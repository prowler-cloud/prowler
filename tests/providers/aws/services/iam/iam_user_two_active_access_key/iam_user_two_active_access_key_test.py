from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_iam

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_iam_user_two_active_access_key:
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
        )

        return audit_info

    @mock_iam
    def test_iam_user_two_active_access_key(self):
        # Create IAM Mocked Resources
        iam_client = client("iam")
        user = "test1"
        user_arn = iam_client.create_user(UserName=user)["User"]["Arn"]
        # Create Access Key 1
        iam_client.create_access_key(UserName=user)
        # Create Access Key 2
        iam_client.create_access_key(UserName=user)

        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_user_two_active_access_key.iam_user_two_active_access_key.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_user_two_active_access_key.iam_user_two_active_access_key import (
                iam_user_two_active_access_key,
            )

            check = iam_user_two_active_access_key()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == user
            assert result[0].resource_arn == user_arn
            assert search(
                f"User {user} has 2 active access keys.", result[0].status_extended
            )

    @mock_iam
    def test_iam_user_one_active_access_key(self):
        # Create IAM User
        iam_client = client("iam")
        user = "test1"
        user_arn = iam_client.create_user(UserName=user)["User"]["Arn"]
        # Create Access Key 1
        iam_client.create_access_key(UserName=user)

        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_user_two_active_access_key.iam_user_two_active_access_key.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_user_two_active_access_key.iam_user_two_active_access_key import (
                iam_user_two_active_access_key,
            )

            check = iam_user_two_active_access_key()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == user
            assert result[0].resource_arn == user_arn
            assert search(
                f"User {user} does not have 2 active access keys.",
                result[0].status_extended,
            )

    @mock_iam
    def test_iam_user_without_active_access_key(self):
        # Create IAM User
        iam_client = client("iam")
        user = "test1"
        user_arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_user_two_active_access_key.iam_user_two_active_access_key.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_user_two_active_access_key.iam_user_two_active_access_key import (
                iam_user_two_active_access_key,
            )

            check = iam_user_two_active_access_key()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == user
            assert result[0].resource_arn == user_arn
            assert search(
                f"User {user} does not have 2 active access keys.",
                result[0].status_extended,
            )

    @mock_iam
    def test_iam_no_users(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_user_two_active_access_key.iam_user_two_active_access_key.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_user_two_active_access_key.iam_user_two_active_access_key import (
                iam_user_two_active_access_key,
            )

            check = iam_user_two_active_access_key()
            result = check.execute()

            assert len(result) == 0
