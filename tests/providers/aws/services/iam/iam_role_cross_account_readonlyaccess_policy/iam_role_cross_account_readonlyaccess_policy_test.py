from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.iam.iam_service import Role
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

AWS_REGION = "us-east-1"
AWS_ACCOUNT_ID = "123456789012"


class Test_iam_role_cross_account_readonlyaccess_policy:
    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_no_roles(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy.iam_client",
            new=IAM(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy import (
                iam_role_cross_account_readonlyaccess_policy,
            )

            check = iam_role_cross_account_readonlyaccess_policy()
            result = check.execute()
            assert len(result) == 0

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_role_without_readonlyaccess_policy(self):
        iam = client("iam")
        role_name = "test"
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": {
                "Sid": "test",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"},
                "Action": "sts:AssumeRole",
            },
        }
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(assume_role_policy_document),
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy.iam_client",
            new=IAM(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy import (
                iam_role_cross_account_readonlyaccess_policy,
            )

            check = iam_role_cross_account_readonlyaccess_policy()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "IAM Role test does not have ReadOnlyAccess policy."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == response["Role"]["Arn"]
            assert result[0].resource_tags == []

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_internal_role_with_readonlyaccess_policy(self):
        iam = client("iam")
        role_name = "test"
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": {
                "Sid": "test",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"},
                "Action": "sts:AssumeRole",
            },
        }
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(assume_role_policy_document),
        )
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess",
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy.iam_client",
            new=IAM(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy import (
                iam_role_cross_account_readonlyaccess_policy,
            )

            check = iam_role_cross_account_readonlyaccess_policy()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "IAM Role test has read-only access but is not cross account."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == response["Role"]["Arn"]
            assert result[0].resource_tags == []

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_cross_account_role_with_readonlyaccess_policy(self):
        iam = client("iam")
        role_name = "test"
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": {
                "Sid": "test",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::012345678910:root"},
                "Action": "sts:AssumeRole",
            },
        }
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(assume_role_policy_document),
        )
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess",
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy.iam_client",
            new=IAM(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy import (
                iam_role_cross_account_readonlyaccess_policy,
            )

            check = iam_role_cross_account_readonlyaccess_policy()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "IAM Role test gives cross account read-only access."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == response["Role"]["Arn"]
            assert result[0].resource_tags == []

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_asterisk_cross_account_role_with_readonlyaccess_policy(self):
        iam = client("iam")
        role_name = "test"
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": {
                "Sid": "test",
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole",
            },
        }
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(assume_role_policy_document),
        )
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess",
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy.iam_client",
            new=IAM(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy import (
                iam_role_cross_account_readonlyaccess_policy,
            )

            check = iam_role_cross_account_readonlyaccess_policy()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "IAM Role test gives cross account read-only access."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == response["Role"]["Arn"]
            assert result[0].resource_tags == []

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
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

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy.iam_client",
            new=iam_client,
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy import (
                iam_role_cross_account_readonlyaccess_policy,
            )

            check = iam_role_cross_account_readonlyaccess_policy()
            result = check.execute()
            assert len(result) == 0
