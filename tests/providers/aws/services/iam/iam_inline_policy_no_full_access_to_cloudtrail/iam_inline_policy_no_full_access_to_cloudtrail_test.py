from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.iam.iam_service import IAM
from tests.providers.aws.utils import (
    ADMINISTRATOR_ROLE_ASSUME_ROLE_POLICY,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)


class Test_iam_inline_policy_no_full_access_to_cloudtrail:
    @mock_aws
    def test_policy_full_access_to_cloudtrail_with_actions(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        # Create IAM Role
        role_name = "test_role"
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(ADMINISTRATOR_ROLE_ASSUME_ROLE_POLICY),
        )["Role"]["Arn"]

        # Put Role Policy
        policy_name = "policy_cloudtrail_full"
        policy_document_full_access = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "cloudtrail:*", "Resource": "*"},
            ],
        }
        _ = iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=dumps(policy_document_full_access),
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_inline_policy_no_full_access_to_cloudtrail.iam_inline_policy_no_full_access_to_cloudtrail.iam_client",
            new=IAM(aws_provider),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_full_access_to_cloudtrail.iam_inline_policy_no_full_access_to_cloudtrail import (
                iam_inline_policy_no_full_access_to_cloudtrail,
            )

            check = iam_inline_policy_no_full_access_to_cloudtrail()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Inline policy {policy_name} attached to role {role_name} allows 'cloudtrail:*' privileges to all resources."
            )
            assert result[0].resource_id == f"test_role/{policy_name}"
            assert result[0].resource_arn == role_arn
            assert result[0].region == "eu-west-1"

    @mock_aws
    def test_policy_no_full_access_to_cloudtrail_with_actions(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        # Create IAM Role
        role_name = "test_role"
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(ADMINISTRATOR_ROLE_ASSUME_ROLE_POLICY),
        )["Role"]["Arn"]

        # Put Role Policy
        policy_name = "policy_no_cloudtrail_full"
        policy_document_full_access = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "ec2:*", "Resource": "*"},
            ],
        }
        _ = iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=dumps(policy_document_full_access),
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_inline_policy_no_full_access_to_cloudtrail.iam_inline_policy_no_full_access_to_cloudtrail.iam_client",
            new=IAM(aws_provider),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_full_access_to_cloudtrail.iam_inline_policy_no_full_access_to_cloudtrail import (
                iam_inline_policy_no_full_access_to_cloudtrail,
            )

            check = iam_inline_policy_no_full_access_to_cloudtrail()
            result = check.execute()
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Inline policy {policy_name} attached to role {role_name} does not allow 'cloudtrail:*' privileges."
            )
            assert result[0].resource_id == f"test_role/{policy_name}"
            assert result[0].resource_arn == role_arn
            assert result[0].region == "eu-west-1"

    @mock_aws
    def test_policy_full_access_to_cloudtrail_with_no_actions(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        # Create IAM Role
        role_name = "test_role"
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(ADMINISTRATOR_ROLE_ASSUME_ROLE_POLICY),
        )["Role"]["Arn"]

        # Put Role Policy
        policy_name = "policy_cloudtrail_full"
        policy_document_full_access = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "NotAction": ["ec2:*", "s3:*"], "Resource": "*"},
            ],
        }
        _ = iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=dumps(policy_document_full_access),
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_inline_policy_no_full_access_to_cloudtrail.iam_inline_policy_no_full_access_to_cloudtrail.iam_client",
            new=IAM(aws_provider),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_full_access_to_cloudtrail.iam_inline_policy_no_full_access_to_cloudtrail import (
                iam_inline_policy_no_full_access_to_cloudtrail,
            )

            check = iam_inline_policy_no_full_access_to_cloudtrail()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Inline policy {policy_name} attached to role {role_name} allows 'cloudtrail:*' privileges to all resources."
            )
            assert result[0].resource_id == f"test_role/{policy_name}"
            assert result[0].resource_arn == role_arn
            assert result[0].region == "eu-west-1"

    @mock_aws
    def test_policy_no_full_access_to_cloudtrail_with_no_actions(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        # Create IAM Role
        role_name = "test_role"
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(ADMINISTRATOR_ROLE_ASSUME_ROLE_POLICY),
        )["Role"]["Arn"]

        # Put Role Policy
        policy_name = "policy_no_cloudtrail_full"
        policy_document_full_access = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotAction": ["ec2:*", "s3:*", "cloudtrail:*"],
                    "Resource": "*",
                },
            ],
        }
        _ = iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=dumps(policy_document_full_access),
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_inline_policy_no_full_access_to_cloudtrail.iam_inline_policy_no_full_access_to_cloudtrail.iam_client",
            new=IAM(aws_provider),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_full_access_to_cloudtrail.iam_inline_policy_no_full_access_to_cloudtrail import (
                iam_inline_policy_no_full_access_to_cloudtrail,
            )

            check = iam_inline_policy_no_full_access_to_cloudtrail()
            result = check.execute()
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Inline policy {policy_name} attached to role {role_name} does not allow 'cloudtrail:*' privileges."
            )
            assert result[0].resource_id == f"test_role/{policy_name}"
            assert result[0].resource_arn == role_arn
            assert result[0].region == "eu-west-1"

    @mock_aws
    def test_policy_full_access_to_cloudtrail_with_multiple_actions(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        # Create IAM Role
        role_name = "test_role"
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(ADMINISTRATOR_ROLE_ASSUME_ROLE_POLICY),
        )["Role"]["Arn"]

        # Put Role Policy
        policy_name = "policy_cloudtrail_full"
        policy_document_full_access = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["cloudtrail:*", "s3:*", "ec2:*"],
                    "Resource": "*",
                },
            ],
        }
        _ = iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=dumps(policy_document_full_access),
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_inline_policy_no_full_access_to_cloudtrail.iam_inline_policy_no_full_access_to_cloudtrail.iam_client",
            new=IAM(aws_provider),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_full_access_to_cloudtrail.iam_inline_policy_no_full_access_to_cloudtrail import (
                iam_inline_policy_no_full_access_to_cloudtrail,
            )

            check = iam_inline_policy_no_full_access_to_cloudtrail()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Inline policy {policy_name} attached to role {role_name} allows 'cloudtrail:*' privileges to all resources."
            )
            assert result[0].resource_id == f"test_role/{policy_name}"
            assert result[0].resource_arn == role_arn
            assert result[0].region == "eu-west-1"
