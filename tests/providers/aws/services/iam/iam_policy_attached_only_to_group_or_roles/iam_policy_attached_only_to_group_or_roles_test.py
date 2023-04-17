from json import dumps
from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_iam

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_iam_policy_attached_only_to_group_or_roles:
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
    def test_iam_user_attached_policy(self):
        result = []
        iam_client = client("iam")
        user = "test_attached_policy"
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "logs:CreateLogGroup", "Resource": "*"},
            ],
        }
        iam_client.create_user(UserName=user)
        policyArn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]
        iam_client.attach_user_policy(UserName=user, PolicyArn=policyArn)

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_policy_attached_only_to_group_or_roles.iam_policy_attached_only_to_group_or_roles.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_policy_attached_only_to_group_or_roles.iam_policy_attached_only_to_group_or_roles import (
                iam_policy_attached_only_to_group_or_roles,
            )

            check = iam_policy_attached_only_to_group_or_roles()
            result = check.execute()
            assert result[0].status == "FAIL"

    @mock_iam
    def test_iam_user_attached_and_inline_policy(self):
        result = []
        iam_client = client("iam")
        user = "test_inline_policy"
        policyName = "policy1"
        policyDocument = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "logs:CreateLogGroup", "Resource": "*"},
            ],
        }
        iam_client.create_user(UserName=user)
        iam_client.put_user_policy(
            UserName=user, PolicyName=policyName, PolicyDocument=dumps(policyDocument)
        )
        policyArn = iam_client.create_policy(
            PolicyName=policyName, PolicyDocument=dumps(policyDocument)
        )["Policy"]["Arn"]
        iam_client.attach_user_policy(UserName=user, PolicyArn=policyArn)

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_policy_attached_only_to_group_or_roles.iam_policy_attached_only_to_group_or_roles.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_policy_attached_only_to_group_or_roles.iam_policy_attached_only_to_group_or_roles import (
                iam_policy_attached_only_to_group_or_roles,
            )

            check = iam_policy_attached_only_to_group_or_roles()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "FAIL"
            assert result[1].status == "FAIL"
            assert search(
                f"User {user} has attached the following policy",
                result[0].status_extended,
            )
            assert search(
                f"User {user} has the following inline policy",
                result[1].status_extended,
            )

    @mock_iam
    def test_iam_user_inline_policy(self):
        result = []
        iam_client = client("iam")
        user = "test_attached_inline_policy"
        policyName = "policy1"
        policyDocument = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "logs:CreateLogGroup", "Resource": "*"},
            ],
        }
        iam_client.create_user(UserName=user)
        iam_client.put_user_policy(
            UserName=user, PolicyName=policyName, PolicyDocument=dumps(policyDocument)
        )

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_policy_attached_only_to_group_or_roles.iam_policy_attached_only_to_group_or_roles.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_policy_attached_only_to_group_or_roles.iam_policy_attached_only_to_group_or_roles import (
                iam_policy_attached_only_to_group_or_roles,
            )

            check = iam_policy_attached_only_to_group_or_roles()
            result = check.execute()
            assert result[0].status == "FAIL"

    @mock_iam
    def test_iam_user_no_policies(self):
        result = []
        iam_client = client("iam")
        user = "test_no_policies"
        iam_client.create_user(UserName=user)

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_policy_attached_only_to_group_or_roles.iam_policy_attached_only_to_group_or_roles.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_policy_attached_only_to_group_or_roles.iam_policy_attached_only_to_group_or_roles import (
                iam_policy_attached_only_to_group_or_roles,
            )

            check = iam_policy_attached_only_to_group_or_roles()
            result = check.execute()
            assert result[0].status == "PASS"
