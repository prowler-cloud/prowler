from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.iam.iam_service import Role
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

AWS_ACCOUNT_ID = "123456789012"

ASSUME_ROLE_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": {
        "Sid": "test",
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"},
        "Action": "sts:AssumeRole",
    },
}


class Test_bedrock_full_access_policy_attached:
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
                "prowler.providers.aws.services.bedrock.bedrock_full_access_policy_attached.bedrock_full_access_policy_attached.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_full_access_policy_attached.bedrock_full_access_policy_attached import (
                bedrock_full_access_policy_attached,
            )

            check = bedrock_full_access_policy_attached()
            result = check.execute()
            assert len(result) == 0

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_role_without_bedrock_full_access_policy(self):
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
                "prowler.providers.aws.services.bedrock.bedrock_full_access_policy_attached.bedrock_full_access_policy_attached.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_full_access_policy_attached.bedrock_full_access_policy_attached import (
                bedrock_full_access_policy_attached,
            )

            check = bedrock_full_access_policy_attached()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "IAM Role test does not have AmazonBedrockFullAccess policy attached."
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
                "prowler.providers.aws.services.bedrock.bedrock_full_access_policy_attached.bedrock_full_access_policy_attached.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_full_access_policy_attached.bedrock_full_access_policy_attached import (
                bedrock_full_access_policy_attached,
            )

            check = bedrock_full_access_policy_attached()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "IAM Role test does not have AmazonBedrockFullAccess policy attached."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == response["Role"]["Arn"]
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_role_with_bedrock_full_access_policy(self):
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
                "prowler.providers.aws.services.bedrock.bedrock_full_access_policy_attached.bedrock_full_access_policy_attached.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_full_access_policy_attached.bedrock_full_access_policy_attached import (
                bedrock_full_access_policy_attached,
            )

            check = bedrock_full_access_policy_attached()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "IAM Role test has AmazonBedrockFullAccess policy attached."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == response["Role"]["Arn"]
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_asterisk_principal_role_with_bedrock_full_access_policy(self):
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
                "prowler.providers.aws.services.bedrock.bedrock_full_access_policy_attached.bedrock_full_access_policy_attached.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_full_access_policy_attached.bedrock_full_access_policy_attached import (
                bedrock_full_access_policy_attached,
            )

            check = bedrock_full_access_policy_attached()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "IAM Role test has AmazonBedrockFullAccess policy attached."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == response["Role"]["Arn"]
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_multiple_roles_mixed_policies(self):
        iam = client("iam")

        # Create a compliant role (no AmazonBedrockFullAccess)
        compliant_response = iam.create_role(
            RoleName="compliant-role",
            AssumeRolePolicyDocument=dumps(ASSUME_ROLE_POLICY_DOCUMENT),
        )
        iam.attach_role_policy(
            RoleName="compliant-role",
            PolicyArn="arn:aws:iam::aws:policy/SecurityAudit",
        )

        # Create a non-compliant role (with AmazonBedrockFullAccess)
        non_compliant_response = iam.create_role(
            RoleName="non-compliant-role",
            AssumeRolePolicyDocument=dumps(ASSUME_ROLE_POLICY_DOCUMENT),
        )
        iam.attach_role_policy(
            RoleName="non-compliant-role",
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
                "prowler.providers.aws.services.bedrock.bedrock_full_access_policy_attached.bedrock_full_access_policy_attached.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_full_access_policy_attached.bedrock_full_access_policy_attached import (
                bedrock_full_access_policy_attached,
            )

            check = bedrock_full_access_policy_attached()
            result = check.execute()
            assert len(result) == 2

            # Sort results by resource_id for deterministic assertions
            result = sorted(result, key=lambda r: r.resource_id)

            # Compliant role
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "IAM Role compliant-role does not have AmazonBedrockFullAccess policy attached."
            )
            assert result[0].resource_id == "compliant-role"
            assert result[0].resource_arn == compliant_response["Role"]["Arn"]
            assert result[0].region == AWS_REGION_US_EAST_1

            # Non-compliant role
            assert result[1].status == "FAIL"
            assert (
                result[1].status_extended
                == "IAM Role non-compliant-role has AmazonBedrockFullAccess policy attached."
            )
            assert result[1].resource_id == "non-compliant-role"
            assert result[1].resource_arn == non_compliant_response["Role"]["Arn"]
            assert result[1].region == AWS_REGION_US_EAST_1

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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_full_access_policy_attached.bedrock_full_access_policy_attached.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_full_access_policy_attached.bedrock_full_access_policy_attached import (
                bedrock_full_access_policy_attached,
            )

            check = bedrock_full_access_policy_attached()
            result = check.execute()
            assert len(result) == 0

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
                "prowler.providers.aws.services.bedrock.bedrock_full_access_policy_attached.bedrock_full_access_policy_attached.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_full_access_policy_attached.bedrock_full_access_policy_attached import (
                bedrock_full_access_policy_attached,
            )

            check = bedrock_full_access_policy_attached()
            result = check.execute()
            assert len(result) == 0
