from json import dumps
from re import search
from unittest import mock

from boto3 import client
from moto import mock_iam


class Test_iam_support_role_created:
    @mock_iam
    def test_support_role_created(self):
        iam_client = client("iam")
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
        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(assume_role_policy_document),
        )
        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy",
        )

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "providers.aws.services.iam.iam_support_role_created.iam_support_role_created.iam_client",
            new=IAM(current_audit_info),
        ):
            from providers.aws.services.iam.iam_support_role_created.iam_support_role_created import (
                iam_support_role_created,
            )

            check = iam_support_role_created()
            result = check.execute()
            assert result[0].status == "PASS"
            assert search(
                f"Support policy attached to role {role_name}",
                result[0].status_extended,
            )

    @mock_iam
    def test_no_support_role_created(self):
        iam_client = client("iam")
        iam_client.list_entities_for_policy(
            PolicyArn="arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy",
            EntityFilter="Role",
        )["PolicyRoles"]

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "providers.aws.services.iam.iam_support_role_created.iam_support_role_created.iam_client",
            new=IAM(current_audit_info),
        ):
            from providers.aws.services.iam.iam_support_role_created.iam_support_role_created import (
                iam_support_role_created,
            )

        check = iam_support_role_created()
        result = check.execute()
        assert result[0].status == "FAIL"
