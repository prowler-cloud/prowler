from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.iam.iam_service import Role
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

AWS_ACCOUNT_ID = "123456789012"
SAGEMAKER_FULL_ACCESS_ARN = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"

ASSUME_ROLE_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": {
        "Sid": "test",
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"},
        "Action": "sts:AssumeRole",
    },
}


class Test_sagemaker_full_access_policy_attached:

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_no_roles(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_full_access_policy_attached.sagemaker_full_access_policy_attached.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_full_access_policy_attached.sagemaker_full_access_policy_attached import (
                sagemaker_full_access_policy_attached,
            )

            check = sagemaker_full_access_policy_attached()
            result = check.execute()
            assert len(result) == 0

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_role_without_sagemaker_full_access_policy(self):
        iam = client("iam")
        role_name = "test"
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(ASSUME_ROLE_POLICY_DOCUMENT),
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_full_access_policy_attached.sagemaker_full_access_policy_attached.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_full_access_policy_attached.sagemaker_full_access_policy_attached import (
                sagemaker_full_access_policy_attached,
            )

            check = sagemaker_full_access_policy_attached()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "IAM Role test does not have AmazonSageMakerFullAccess policy attached."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == response["Role"]["Arn"]
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_role_with_other_policy(self):
        iam = client("iam")
        role_name = "test"
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(ASSUME_ROLE_POLICY_DOCUMENT),
        )
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/SecurityAudit",
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_full_access_policy_attached.sagemaker_full_access_policy_attached.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_full_access_policy_attached.sagemaker_full_access_policy_attached import (
                sagemaker_full_access_policy_attached,
            )

            check = sagemaker_full_access_policy_attached()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "IAM Role test does not have AmazonSageMakerFullAccess policy attached."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == response["Role"]["Arn"]
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_role_with_unrelated_full_access_policy(self):
        iam = client("iam")
        role_name = "test"
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(ASSUME_ROLE_POLICY_DOCUMENT),
        )
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/AmazonBedrockFullAccess",
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_full_access_policy_attached.sagemaker_full_access_policy_attached.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_full_access_policy_attached.sagemaker_full_access_policy_attached import (
                sagemaker_full_access_policy_attached,
            )

            check = sagemaker_full_access_policy_attached()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "IAM Role test does not have AmazonSageMakerFullAccess policy attached."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == response["Role"]["Arn"]
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_role_with_sagemaker_full_access_policy(self):
        iam = client("iam")
        role_name = "test"
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(ASSUME_ROLE_POLICY_DOCUMENT),
        )
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn=SAGEMAKER_FULL_ACCESS_ARN,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_full_access_policy_attached.sagemaker_full_access_policy_attached.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_full_access_policy_attached.sagemaker_full_access_policy_attached import (
                sagemaker_full_access_policy_attached,
            )

            check = sagemaker_full_access_policy_attached()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "IAM Role test has AmazonSageMakerFullAccess policy attached."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == response["Role"]["Arn"]
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_only_aws_service_linked_roles(self):
        iam_client = mock.MagicMock
        iam_client.roles = []
        iam_client.roles.append(
            Role(
                name="AWSServiceRoleForAmazonSageMakerNotebooks",
                arn="arn:aws:iam::106908755756:role/aws-service-role/sagemaker.amazonaws.com/AWSServiceRoleForAmazonSageMakerNotebooks",
                assume_role_policy={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "sagemaker.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                is_service_role=True,
            )
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_full_access_policy_attached.sagemaker_full_access_policy_attached.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_full_access_policy_attached.sagemaker_full_access_policy_attached import (
                sagemaker_full_access_policy_attached,
            )

            check = sagemaker_full_access_policy_attached()
            result = check.execute()
            assert len(result) == 0

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_customer_created_service_role_is_evaluated(self):
        """A role trusted only by sagemaker.amazonaws.com but NOT under the
        aws-service-role path is customer-created, so it must be evaluated."""
        iam_client = mock.MagicMock
        iam_client.region = AWS_REGION_US_EAST_1
        iam_client.roles = []
        iam_client.roles.append(
            Role(
                name="SageMakerExecutionRole",
                arn=f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/SageMakerExecutionRole",
                assume_role_policy={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "sagemaker.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                is_service_role=True,
                attached_policies=[
                    {
                        "PolicyName": "AmazonSageMakerFullAccess",
                        "PolicyArn": SAGEMAKER_FULL_ACCESS_ARN,
                    }
                ],
            )
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_full_access_policy_attached.sagemaker_full_access_policy_attached.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_full_access_policy_attached.sagemaker_full_access_policy_attached import (
                sagemaker_full_access_policy_attached,
            )

            check = sagemaker_full_access_policy_attached()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "IAM Role SageMakerExecutionRole has AmazonSageMakerFullAccess policy attached."
            )

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_access_denied(self):
        iam_client = mock.MagicMock
        iam_client.roles = None

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_full_access_policy_attached.sagemaker_full_access_policy_attached.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_full_access_policy_attached.sagemaker_full_access_policy_attached import (
                sagemaker_full_access_policy_attached,
            )

            check = sagemaker_full_access_policy_attached()
            result = check.execute()
            assert len(result) == 0
