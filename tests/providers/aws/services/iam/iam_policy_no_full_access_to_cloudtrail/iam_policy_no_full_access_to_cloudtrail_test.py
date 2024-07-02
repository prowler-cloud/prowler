from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.iam.iam_service import IAM
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_iam_policy_no_full_access_to_cloudtrail:
    @mock_aws
    def test_policy_full_access_to_cloudtrail(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        policy_name = "policy_cloudtrail_full"
        policy_document_full_access = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "cloudtrail:*", "Resource": "*"},
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document_full_access)
        )["Policy"]["Arn"]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_no_full_access_to_cloudtrail.iam_policy_no_full_access_to_cloudtrail.iam_client",
                new=IAM(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_policy_no_full_access_to_cloudtrail.iam_policy_no_full_access_to_cloudtrail import (
                    iam_policy_no_full_access_to_cloudtrail,
                )

                check = iam_policy_no_full_access_to_cloudtrail()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"Custom Policy {policy_name} allows 'cloudtrail:*' privileges."
                )
                assert result[0].resource_id == "policy_cloudtrail_full"
                assert result[0].resource_arn == arn
                assert result[0].region == "us-east-1"

    @mock_aws
    def test_policy_no_full_access_to_cloudtrail(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        policy_name = "policy_no_cloudtrail_full"
        policy_document_full_access = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "ec2:*", "Resource": "*"},
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document_full_access)
        )["Policy"]["Arn"]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_no_full_access_to_cloudtrail.iam_policy_no_full_access_to_cloudtrail.iam_client",
                new=IAM(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_policy_no_full_access_to_cloudtrail.iam_policy_no_full_access_to_cloudtrail import (
                    iam_policy_no_full_access_to_cloudtrail,
                )

                check = iam_policy_no_full_access_to_cloudtrail()
                result = check.execute()
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Custom Policy {policy_name} does not allow 'cloudtrail:*' privileges."
                )
                assert result[0].resource_id == "policy_no_cloudtrail_full"
                assert result[0].resource_arn == arn
                assert result[0].region == "us-east-1"

    @mock_aws
    def test_policy_mixed(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        policy_name = "policy_mixed"
        policy_document_full_access = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["ec2:*", "cloudtrail:*"],
                    "Resource": "*",
                },
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document_full_access)
        )["Policy"]["Arn"]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_no_full_access_to_cloudtrail.iam_policy_no_full_access_to_cloudtrail.iam_client",
                new=IAM(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_policy_no_full_access_to_cloudtrail.iam_policy_no_full_access_to_cloudtrail import (
                    iam_policy_no_full_access_to_cloudtrail,
                )

                check = iam_policy_no_full_access_to_cloudtrail()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"Custom Policy {policy_name} allows 'cloudtrail:*' privileges."
                )
                assert result[0].resource_id == "policy_mixed"
                assert result[0].resource_arn == arn
                assert result[0].region == "us-east-1"

    @mock_aws
    def test_policy_full_access_to_cloudtrail_through_no_actions(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        policy_name = "policy_cloudtrail_full_no_actions"
        policy_document_full_access = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "NotAction": ["ec2:*", "s3:*"], "Resource": "*"},
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document_full_access)
        )["Policy"]["Arn"]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_no_full_access_to_cloudtrail.iam_policy_no_full_access_to_cloudtrail.iam_client",
                new=IAM(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_policy_no_full_access_to_cloudtrail.iam_policy_no_full_access_to_cloudtrail import (
                    iam_policy_no_full_access_to_cloudtrail,
                )

                check = iam_policy_no_full_access_to_cloudtrail()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"Custom Policy {policy_name} allows 'cloudtrail:*' privileges."
                )
                assert result[0].resource_id == "policy_cloudtrail_full_no_actions"
                assert result[0].resource_arn == arn
                assert result[0].region == "us-east-1"

    @mock_aws
    def test_policy_no_full_access_to_cloudtrail_through_no_actions(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        policy_name = "policy_no_cloudtrail_full_no_actions"
        policy_document_no_full_access = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "NotAction": ["cloudtrail:*"], "Resource": "*"},
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document_no_full_access)
        )["Policy"]["Arn"]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_no_full_access_to_cloudtrail.iam_policy_no_full_access_to_cloudtrail.iam_client",
                new=IAM(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_policy_no_full_access_to_cloudtrail.iam_policy_no_full_access_to_cloudtrail import (
                    iam_policy_no_full_access_to_cloudtrail,
                )

                check = iam_policy_no_full_access_to_cloudtrail()
                result = check.execute()
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Custom Policy {policy_name} does not allow 'cloudtrail:*' privileges."
                )
                assert result[0].resource_id == "policy_no_cloudtrail_full_no_actions"
                assert result[0].resource_arn == arn
                assert result[0].region == "us-east-1"
