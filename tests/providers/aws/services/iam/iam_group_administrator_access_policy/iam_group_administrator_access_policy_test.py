from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider


class Test_iam_group_administrator_access_policy:
    def test_no_users(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_group_administrator_access_policy.iam_group_administrator_access_policy.iam_client",
            new=IAM(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_group_administrator_access_policy.iam_group_administrator_access_policy import (
                iam_group_administrator_access_policy,
            )

            check = iam_group_administrator_access_policy()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_no_admin_groups(self):
        iam = client("iam", region_name=AWS_REGION_EU_WEST_1)
        group_arn = iam.create_group(GroupName="test_group")["Group"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_group_administrator_access_policy.iam_group_administrator_access_policy.iam_client",
            new=IAM(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_group_administrator_access_policy.iam_group_administrator_access_policy import (
                iam_group_administrator_access_policy,
            )

            check = iam_group_administrator_access_policy()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "IAM Group test_group does not have AdministratorAccess policy."
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == "test_group"
            assert result[0].resource_arn == group_arn

    @mock_aws
    def test_admin_groups(self):
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)

        # Create the AdministratorAccess policy
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }

        policy_arn = iam_client.create_policy(
            PolicyName="AdministratorAccess",
            PolicyDocument=dumps(policy_document),
            Path="/",
        )["Policy"]["Arn"]

        # Create the test group
        group_arn = iam_client.create_group(GroupName="test_group")["Group"]["Arn"]

        # Attach the AdministratorAccess policy to the test group
        iam_client.attach_group_policy(GroupName="test_group", PolicyArn=policy_arn)

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_group_administrator_access_policy.iam_group_administrator_access_policy.iam_client",
            new=IAM(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_group_administrator_access_policy.iam_group_administrator_access_policy import (
                iam_group_administrator_access_policy,
            )

            check = iam_group_administrator_access_policy()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "IAM Group test_group has AdministratorAccess policy attached."
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == "test_group"
            assert result[0].resource_arn == group_arn
