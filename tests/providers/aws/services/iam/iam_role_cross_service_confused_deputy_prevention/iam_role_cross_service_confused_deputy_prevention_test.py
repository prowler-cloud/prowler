from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.iam.iam_service import Role
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

AWS_REGION = "us-east-1"
AWS_ACCOUNT_ID = "123456789012"


class Test_iam_role_cross_service_confused_deputy_prevention:
    @mock_aws
    def test_no_roles(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        aws_provider.identity.account = AWS_ACCOUNT_ID
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_role_cross_service_confused_deputy_prevention.iam_role_cross_service_confused_deputy_prevention.iam_client",
            new=IAM(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_role_cross_service_confused_deputy_prevention.iam_role_cross_service_confused_deputy_prevention import (
                iam_role_cross_service_confused_deputy_prevention,
            )

            check = iam_role_cross_service_confused_deputy_prevention()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_only_aws_service_linked_roles(self):
        iam_client = mock.MagicMock
        iam_client.roles = []
        iam_client.roles.append(
            Role(
                name="AWSServiceRoleForAmazonGuardDuty",
                arn="arn:aws:iam::106908755756:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty",
                assume_role_policy={
                    "Version": "2008-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                is_service_role=True,
            )
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        aws_provider.identity.account = AWS_ACCOUNT_ID

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_role_cross_service_confused_deputy_prevention.iam_role_cross_service_confused_deputy_prevention.iam_client",
            new=iam_client,
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_role_cross_service_confused_deputy_prevention.iam_role_cross_service_confused_deputy_prevention import (
                iam_role_cross_service_confused_deputy_prevention,
            )

            check = iam_role_cross_service_confused_deputy_prevention()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
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

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        aws_provider.identity.account = AWS_ACCOUNT_ID
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_role_cross_service_confused_deputy_prevention.iam_role_cross_service_confused_deputy_prevention.iam_client",
            new=IAM(aws_provider),
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
                == "IAM Service Role test does not prevent against a cross-service confused deputy attack."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == response["Role"]["Arn"]

    @mock_aws
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

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        aws_provider.identity.account = AWS_ACCOUNT_ID
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_role_cross_service_confused_deputy_prevention.iam_role_cross_service_confused_deputy_prevention.iam_client",
            new=IAM(aws_provider),
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
                == "IAM Service Role test prevents against a cross-service confused deputy attack."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == response["Role"]["Arn"]

    @mock_aws
    def test_iam_service_role_with_cross_service_confused_deputy_prevention_stringlike(
        self,
    ):
        iam_client = client("iam", region_name=AWS_REGION)
        policy_document = {
            "Version": "2008-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "workspaces.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringLike": {"aws:SourceAccount": [AWS_ACCOUNT_ID]}
                    },
                }
            ],
        }
        response = iam_client.create_role(
            RoleName="test",
            AssumeRolePolicyDocument=dumps(policy_document),
        )

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        aws_provider.identity.account = AWS_ACCOUNT_ID
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_role_cross_service_confused_deputy_prevention.iam_role_cross_service_confused_deputy_prevention.iam_client",
            new=IAM(aws_provider),
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
                == "IAM Service Role test prevents against a cross-service confused deputy attack."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == response["Role"]["Arn"]

    @mock_aws
    def test_iam_service_role_with_cross_service_confused_deputy_prevention_PrincipalAccount(
        self,
    ):
        iam_client = client("iam", region_name=AWS_REGION)
        policy_document = {
            "Version": "2008-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "workspaces.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringLike": {"aws:PrincipalAccount": [AWS_ACCOUNT_ID]}
                    },
                }
            ],
        }
        response = iam_client.create_role(
            RoleName="test",
            AssumeRolePolicyDocument=dumps(policy_document),
        )

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        aws_provider.identity.account = AWS_ACCOUNT_ID
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_role_cross_service_confused_deputy_prevention.iam_role_cross_service_confused_deputy_prevention.iam_client",
            new=IAM(aws_provider),
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
                == "IAM Service Role test prevents against a cross-service confused deputy attack."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == response["Role"]["Arn"]

    @mock_aws
    def test_iam_service_role_with_cross_service_confused_deputy_prevention_ResourceAccount(
        self,
    ):
        iam_client = client("iam", region_name=AWS_REGION)
        policy_document = {
            "Version": "2008-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "workspaces.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringLike": {"aws:ResourceAccount": [AWS_ACCOUNT_ID]}
                    },
                }
            ],
        }
        response = iam_client.create_role(
            RoleName="test",
            AssumeRolePolicyDocument=dumps(policy_document),
        )

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        aws_provider.identity.account = AWS_ACCOUNT_ID
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_role_cross_service_confused_deputy_prevention.iam_role_cross_service_confused_deputy_prevention.iam_client",
            new=IAM(aws_provider),
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
                == "IAM Service Role test prevents against a cross-service confused deputy attack."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == response["Role"]["Arn"]
