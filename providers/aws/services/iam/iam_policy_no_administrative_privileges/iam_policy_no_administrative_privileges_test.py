from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_iam


class Test_iam_policy_no_administrative_privileges_test:
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
        iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "providers.aws.services.iam.iam_policy_no_administrative_privileges.iam_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from providers.aws.services.iam.iam_policy_no_administrative_privileges.iam_policy_no_administrative_privileges import (
                iam_policy_no_administrative_privileges,
            )

            check = iam_policy_no_administrative_privileges()
            result = check.execute()
            assert result[0].status == "FAIL"

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
        iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "providers.aws.services.iam.iam_policy_no_administrative_privileges.iam_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from providers.aws.services.iam.iam_policy_no_administrative_privileges.iam_policy_no_administrative_privileges import (
                iam_policy_no_administrative_privileges,
            )

            check = iam_policy_no_administrative_privileges()
            result = check.execute()
            assert result[0].status == "PASS"

    @mock_iam
    def test_policy_administrative_and_non_administrative(self):

        iam_client = client("iam")
        policy_name_non_administrative = "policy1"
        policy_document_non_administrative = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "logs:CreateLogGroup", "Resource": "*"},
            ],
        }
        policy_name_administrative = "policy2"
        policy_document_administrative = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
            ],
        }
        iam_client.create_policy(
            PolicyName=policy_name_non_administrative,
            PolicyDocument=dumps(policy_document_non_administrative),
        )["Policy"]["Arn"]
        iam_client.create_policy(
            PolicyName=policy_name_administrative,
            PolicyDocument=dumps(policy_document_administrative),
        )["Policy"]["Arn"]

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "providers.aws.services.iam.iam_policy_no_administrative_privileges.iam_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from providers.aws.services.iam.iam_policy_no_administrative_privileges.iam_policy_no_administrative_privileges import (
                iam_policy_no_administrative_privileges,
            )

            check = iam_policy_no_administrative_privileges()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "PASS"
            assert result[1].status == "FAIL"
