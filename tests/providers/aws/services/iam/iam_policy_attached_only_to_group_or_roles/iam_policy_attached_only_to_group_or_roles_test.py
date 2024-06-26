from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_iam_policy_attached_only_to_group_or_roles:
    @mock_aws
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

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_policy_attached_only_to_group_or_roles.iam_policy_attached_only_to_group_or_roles.iam_client",
            new=IAM(aws_provider),
        ):
            from prowler.providers.aws.services.iam.iam_policy_attached_only_to_group_or_roles.iam_policy_attached_only_to_group_or_roles import (
                iam_policy_attached_only_to_group_or_roles,
            )

            check = iam_policy_attached_only_to_group_or_roles()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"User {user} has the policy {policy_name} attached."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == f"{user}/{policy_name}"
            assert (
                result[0].resource_arn
                == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:user/{user}"
            )

    @mock_aws
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

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_policy_attached_only_to_group_or_roles.iam_policy_attached_only_to_group_or_roles.iam_client",
            new=IAM(aws_provider),
        ):
            from prowler.providers.aws.services.iam.iam_policy_attached_only_to_group_or_roles.iam_policy_attached_only_to_group_or_roles import (
                iam_policy_attached_only_to_group_or_roles,
            )

            check = iam_policy_attached_only_to_group_or_roles()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"User {user} has the policy {policyName} attached."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == f"{user}/{policyName}"

            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"User {user} has the policy {policyName} attached."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == f"{user}/{policyName}"
            assert (
                result[0].resource_arn
                == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:user/{user}"
            )

    @mock_aws
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

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_policy_attached_only_to_group_or_roles.iam_policy_attached_only_to_group_or_roles.iam_client",
            new=IAM(aws_provider),
        ):
            from prowler.providers.aws.services.iam.iam_policy_attached_only_to_group_or_roles.iam_policy_attached_only_to_group_or_roles import (
                iam_policy_attached_only_to_group_or_roles,
            )

            check = iam_policy_attached_only_to_group_or_roles()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"User {user} has the inline policy {policyName} attached."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == f"{user}/{policyName}"
            assert (
                result[0].resource_arn
                == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:user/{user}"
            )

    @mock_aws
    def test_iam_user_no_policies(self):
        result = []
        iam_client = client("iam")
        user = "test_no_policies"
        iam_client.create_user(UserName=user)

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_policy_attached_only_to_group_or_roles.iam_policy_attached_only_to_group_or_roles.iam_client",
            new=IAM(aws_provider),
        ):
            from prowler.providers.aws.services.iam.iam_policy_attached_only_to_group_or_roles.iam_policy_attached_only_to_group_or_roles import (
                iam_policy_attached_only_to_group_or_roles,
            )

            check = iam_policy_attached_only_to_group_or_roles()
            result = check.execute()
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"User {user} has no inline or attached policies."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == user
            assert (
                result[0].resource_arn
                == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:user/{user}"
            )
