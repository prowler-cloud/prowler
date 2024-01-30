from json import dumps
from re import search
from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.iam.iam_service import IAM
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_iam_securityaudit_role_created:
    @mock_aws
    def test_securityaudit_role_created(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        iam = client("iam")
        role_name = "test_securityaudit_role_created"
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
            PolicyArn="arn:aws:iam::aws:policy/SecurityAudit",
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_securityaudit_role_created.iam_securityaudit_role_created.iam_client",
                new=IAM(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_securityaudit_role_created.iam_securityaudit_role_created import (
                    iam_securityaudit_role_created,
                )

                check = iam_securityaudit_role_created()
                result = check.execute()
                assert result[0].status == "PASS"
                assert search(
                    f"SecurityAudit policy attached to role {role_name}.",
                    result[0].status_extended,
                )
                assert result[0].resource_id == "SecurityAudit"
                assert result[0].resource_arn == "arn:aws:iam::aws:policy/SecurityAudit"
                assert result[0].region == "us-east-1"

    @mock_aws
    def test_no_securityaudit_role_created(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_securityaudit_role_created.iam_securityaudit_role_created.iam_client",
                new=IAM(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_securityaudit_role_created.iam_securityaudit_role_created import (
                    iam_securityaudit_role_created,
                )

                check = iam_securityaudit_role_created()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "SecurityAudit policy is not attached to any role."
                )
                assert result[0].resource_id == "SecurityAudit"
                assert result[0].resource_arn == "arn:aws:iam::aws:policy/SecurityAudit"
                assert result[0].region == "us-east-1"
