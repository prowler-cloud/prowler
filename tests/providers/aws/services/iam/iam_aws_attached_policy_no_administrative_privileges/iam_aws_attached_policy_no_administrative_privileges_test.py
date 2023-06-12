from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_iam

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_iam_aws_attached_policy_no_administrative_privileges_test:
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
        )

        return audit_info

    @mock_iam
    def test_policy_with_administrative_privileges(self):
        iam_client = client("iam")

        iam_client.create_role(
            RoleName="my-role", AssumeRolePolicyDocument="{}", Path="/my-path/"
        )
        iam_client.attach_role_policy(
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess", RoleName="my-role"
        )
        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_aws_attached_policy_no_administrative_privileges.iam_aws_attached_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_aws_attached_policy_no_administrative_privileges.iam_aws_attached_policy_no_administrative_privileges import (
                iam_aws_attached_policy_no_administrative_privileges,
            )

            check = iam_aws_attached_policy_no_administrative_privileges()
            results = check.execute()
            for result in results:
                if result.resource_id == "AdministratorAccess":
                    assert result.status == "FAIL"
                    assert (
                        result.resource_arn
                        == "arn:aws:iam::aws:policy/AdministratorAccess"
                    )
                    assert search(
                        "AWS policy AdministratorAccess is attached and allows ",
                        result.status_extended,
                    )

    @mock_iam
    def test_policy_non_administrative(self):
        iam_client = client("iam")

        iam_client.create_role(
            RoleName="my-role", AssumeRolePolicyDocument="{}", Path="/my-path/"
        )
        iam_client.attach_role_policy(
            PolicyArn="arn:aws:iam::aws:policy/IAMUserChangePassword",
            RoleName="my-role",
        )
        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_aws_attached_policy_no_administrative_privileges.iam_aws_attached_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_aws_attached_policy_no_administrative_privileges.iam_aws_attached_policy_no_administrative_privileges import (
                iam_aws_attached_policy_no_administrative_privileges,
            )

            check = iam_aws_attached_policy_no_administrative_privileges()
            results = check.execute()
            for result in results:
                if result.resource_id == "IAMUserChangePassword":
                    assert result.status == "PASS"
                    assert (
                        result.resource_arn
                        == "arn:aws:iam::aws:policy/IAMUserChangePassword"
                    )
                    assert search(
                        "AWS policy IAMUserChangePassword is attached but does not allow",
                        result.status_extended,
                    )

    @mock_iam
    def test_policy_administrative_and_non_administrative(self):
        iam_client = client("iam")

        iam_client.create_role(
            RoleName="my-role", AssumeRolePolicyDocument="{}", Path="/my-path/"
        )
        iam_client.attach_role_policy(
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess", RoleName="my-role"
        )
        iam_client.attach_role_policy(
            PolicyArn="arn:aws:iam::aws:policy/IAMUserChangePassword",
            RoleName="my-role",
        )
        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_aws_attached_policy_no_administrative_privileges.iam_aws_attached_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_aws_attached_policy_no_administrative_privileges.iam_aws_attached_policy_no_administrative_privileges import (
                iam_aws_attached_policy_no_administrative_privileges,
            )

            check = iam_aws_attached_policy_no_administrative_privileges()
            results = check.execute()
            for result in results:
                if result.resource_id == "IAMUserChangePassword":
                    assert result.status == "PASS"
                    assert (
                        result.resource_arn
                        == "arn:aws:iam::aws:policy/IAMUserChangePassword"
                    )
                    assert search(
                        "AWS policy IAMUserChangePassword is attached but does not allow ",
                        result.status_extended,
                    )
                    assert result.resource_id == "IAMUserChangePassword"
                if result.resource_id == "AdministratorAccess":
                    assert result.status == "FAIL"
                    assert (
                        result.resource_arn
                        == "arn:aws:iam::aws:policy/AdministratorAccess"
                    )
                    assert search(
                        "AWS policy AdministratorAccess is attached and allows ",
                        result.status_extended,
                    )
                    assert result.resource_id == "AdministratorAccess"
