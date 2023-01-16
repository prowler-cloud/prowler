from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_iam

AWS_REGION = "us-east-1"
AWS_ACCOUNT_ID = "123456789012"


class Test_iam_role_cross_service_confused_deputy_prevention:
    @mock_iam
    def test_iam_service_role_without_cross_service_confused_deputy_prevention(self):
        iam_client = client("iam", region_name=AWS_REGION)
        policy_document = {
            "Version": "2008-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        response = iam_client.create_role(
            RoleName="test",
            AssumeRolePolicyDocument=dumps(policy_document),
        )

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info.audited_partition = "aws"
        current_audit_info.audited_account = AWS_ACCOUNT_ID
        with mock.patch(
            "prowler.providers.aws.services.iam.iam_role_cross_service_confused_deputy_prevention.iam_role_cross_service_confused_deputy_prevention.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_role_cross_service_confused_deputy_prevention.iam_role_cross_service_confused_deputy_prevention import (
                iam_role_cross_service_confused_deputy_prevention,
            )

            check = iam_role_cross_service_confused_deputy_prevention()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "IAM Service Role test prevents against a cross-service confused deputy attack"
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == response["Role"]["Arn"]

    @mock_iam
    def test_iam_service_role_with_cross_service_confused_deputy_prevention(self):
        iam_client = client("iam", region_name=AWS_REGION)
        policy_document = {
            "Version": "2008-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "workspaces.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": [AWS_ACCOUNT_ID]}
                    },
                }
            ],
        }
        response = iam_client.create_role(
            RoleName="test",
            AssumeRolePolicyDocument=dumps(policy_document),
        )

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info.audited_partition = "aws"
        current_audit_info.audited_account = AWS_ACCOUNT_ID
        with mock.patch(
            "prowler.providers.aws.services.iam.iam_role_cross_service_confused_deputy_prevention.iam_role_cross_service_confused_deputy_prevention.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_role_cross_service_confused_deputy_prevention.iam_role_cross_service_confused_deputy_prevention import (
                iam_role_cross_service_confused_deputy_prevention,
            )

            check = iam_role_cross_service_confused_deputy_prevention()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "IAM Service Role test does not prevent against a cross-service confused deputy attack"
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == response["Role"]["Arn"]
