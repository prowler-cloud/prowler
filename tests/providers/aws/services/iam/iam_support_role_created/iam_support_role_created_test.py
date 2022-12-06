from json import dumps
from re import search
from unittest import mock

from boto3 import client
from moto import mock_iam


class Test_iam_support_role_created:
    @mock_iam
    def test_support_role_created(self):
        iam = client("iam")
        role_name = "test_support"
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": {
                "Sid": "test",
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole",
            },
        }
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(assume_role_policy_document),
        )
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy",
        )

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_support_role_created.iam_support_role_created.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_support_role_created.iam_support_role_created import (
                iam_support_role_created,
            )

            check = iam_support_role_created()
            result = check.execute()
            assert result[0].status == "PASS"
            assert search(
                f"Support policy attached to role {role_name}",
                result[0].status_extended,
            )
            assert result[0].resource_id == "AWSSupportServiceRolePolicy"
            assert (
                result[0].resource_arn
                == "arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy"
            )

    @mock_iam
    def test_no_support_role_created(self):

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_support_role_created.iam_support_role_created.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_support_role_created.iam_support_role_created import (
                iam_support_role_created,
            )

            check = iam_support_role_created()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Support policy is not attached to any role"
            )
            assert result[0].resource_id == "AWSSupportServiceRolePolicy"
            assert (
                result[0].resource_arn
                == "arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy"
            )
