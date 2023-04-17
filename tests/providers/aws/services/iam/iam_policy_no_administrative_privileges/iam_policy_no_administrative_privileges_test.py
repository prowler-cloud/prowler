from json import dumps
from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_iam

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_iam_policy_no_administrative_privileges_test:
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
    def test_policy_administrative(self):
        iam_client = client("iam")
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_policy_no_administrative_privileges.iam_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_policy_no_administrative_privileges.iam_policy_no_administrative_privileges import (
                iam_policy_no_administrative_privileges,
            )

            check = iam_policy_no_administrative_privileges()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert result[0].resource_arn == arn
            assert search(f"Policy {policy_name} allows ", result[0].status_extended)
            assert result[0].resource_id == policy_name

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
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_policy_no_administrative_privileges.iam_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_policy_no_administrative_privileges.iam_policy_no_administrative_privileges import (
                iam_policy_no_administrative_privileges,
            )

            check = iam_policy_no_administrative_privileges()
            result = check.execute()
            assert result[0].status == "PASS"
            assert result[0].resource_arn == arn
            assert search(
                f"Policy {policy_name} does not allow", result[0].status_extended
            )
            assert result[0].resource_id == policy_name

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

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_policy_no_administrative_privileges.iam_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_policy_no_administrative_privileges.iam_policy_no_administrative_privileges import (
                iam_policy_no_administrative_privileges,
            )

            check = iam_policy_no_administrative_privileges()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "PASS"
            assert result[0].resource_arn == arn_non_administrative
            assert search(
                f"Policy {policy_name_non_administrative} does not allow ",
                result[0].status_extended,
            )
            assert result[0].resource_id == policy_name_non_administrative
            assert result[1].status == "FAIL"
            assert result[1].resource_arn == arn_administrative
            assert search(
                f"Policy {policy_name_administrative} allows ",
                result[1].status_extended,
            )
            assert result[1].resource_id == policy_name_administrative
