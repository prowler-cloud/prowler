from json import dumps
from re import search
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_iam_customer_attached_policy_no_administrative_privileges_test:
    @mock_aws
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
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_customer_attached_policy_no_administrative_privileges.iam_customer_attached_policy_no_administrative_privileges.iam_client",
            new=IAM(aws_provider),
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

    @mock_aws
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
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_customer_attached_policy_no_administrative_privileges.iam_customer_attached_policy_no_administrative_privileges.iam_client",
            new=IAM(aws_provider),
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

    @mock_aws
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
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_customer_attached_policy_no_administrative_privileges.iam_customer_attached_policy_no_administrative_privileges.iam_client",
            new=IAM(aws_provider),
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
