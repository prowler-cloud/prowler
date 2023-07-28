from json import dumps
from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_iam

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_iam_customer_attached_policy_no_administrative_privileges_test:
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
    def test_policy_administrative(self):
        iam_client = client("iam")
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
            ],
        }
        iam_client.create_role(
            RoleName="my-role", AssumeRolePolicyDocument="{}", Path="/my-path/"
        )
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]
        iam_client.attach_role_policy(PolicyArn=arn, RoleName="my-role")
        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_customer_attached_policy_no_administrative_privileges.iam_customer_attached_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_customer_attached_policy_no_administrative_privileges.iam_customer_attached_policy_no_administrative_privileges import (
                iam_customer_attached_policy_no_administrative_privileges,
            )

            check = iam_customer_attached_policy_no_administrative_privileges()
            results = check.execute()
            for result in results:
                if result.resource_id == "policy1":
                    assert result.status == "FAIL"
                    assert result.resource_arn == arn
                    assert search(
                        f"Custom policy {policy_name} is attached and allows ",
                        result.status_extended,
                    )

    @mock_iam
    def test_policy_non_administrative(self):
        iam_client = client("iam")
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "logs:CreateLogGroup", "Resource": "*"},
            ],
        }
        iam_client.create_role(
            RoleName="my-role", AssumeRolePolicyDocument="{}", Path="/my-path/"
        )
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]
        iam_client.attach_role_policy(PolicyArn=arn, RoleName="my-role")
        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_customer_attached_policy_no_administrative_privileges.iam_customer_attached_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_customer_attached_policy_no_administrative_privileges.iam_customer_attached_policy_no_administrative_privileges import (
                iam_customer_attached_policy_no_administrative_privileges,
            )

            check = iam_customer_attached_policy_no_administrative_privileges()
            results = check.execute()
            for result in results:
                if result.resource_id == "policy1":
                    assert result.status == "PASS"
                    assert result.resource_arn == arn
                    assert search(
                        f"Custom policy {policy_name} is attached but does not allow",
                        result.status_extended,
                    )

    @mock_iam
    def test_policy_administrative_and_non_administrative(self):
        iam_client = client("iam")
        policy_name_non_administrative = "policy1"
        policy_document_non_administrative = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "logs:*", "Resource": "*"},
            ],
        }
        policy_name_administrative = "policy2"
        policy_document_administrative = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
            ],
        }
        arn_non_administrative = iam_client.create_policy(
            PolicyName=policy_name_non_administrative,
            PolicyDocument=dumps(policy_document_non_administrative),
        )["Policy"]["Arn"]
        arn_administrative = iam_client.create_policy(
            PolicyName=policy_name_administrative,
            PolicyDocument=dumps(policy_document_administrative),
        )["Policy"]["Arn"]
        iam_client.create_role(
            RoleName="my-role", AssumeRolePolicyDocument="{}", Path="/my-path/"
        )
        iam_client.attach_role_policy(
            PolicyArn=arn_non_administrative, RoleName="my-role"
        )
        iam_client.attach_role_policy(PolicyArn=arn_administrative, RoleName="my-role")
        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_customer_attached_policy_no_administrative_privileges.iam_customer_attached_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_customer_attached_policy_no_administrative_privileges.iam_customer_attached_policy_no_administrative_privileges import (
                iam_customer_attached_policy_no_administrative_privileges,
            )

            check = iam_customer_attached_policy_no_administrative_privileges()
            results = check.execute()
            for result in results:
                if result.resource_id == "policy1":
                    assert result.status == "PASS"
                    assert result.resource_arn == arn_non_administrative
                    assert search(
                        f"Custom policy {policy_name_non_administrative} is attached but does not allow ",
                        result.status_extended,
                    )
                    assert result.resource_id == policy_name_non_administrative
                if result.resource_id == "policy2":
                    assert result.status == "FAIL"
                    assert result.resource_arn == arn_administrative
                    assert search(
                        f"Custom policy {policy_name_administrative} is attached and allows ",
                        result.status_extended,
                    )
                    assert result.resource_id == policy_name_administrative
