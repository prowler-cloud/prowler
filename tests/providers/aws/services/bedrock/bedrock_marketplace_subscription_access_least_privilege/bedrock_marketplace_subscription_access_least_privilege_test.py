from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.iam.iam_service import IAM
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

CHECK_MODULE_PATH = "prowler.providers.aws.services.bedrock.bedrock_marketplace_subscription_access_least_privilege.bedrock_marketplace_subscription_access_least_privilege"


class Test_bedrock_marketplace_subscription_access_least_privilege:
    """Tests for the bedrock_marketplace_subscription_access_least_privilege check."""

    @mock_aws
    def test_policy_allows_marketplace_subscribe_on_all_resources(self):
        """FAIL: Policy explicitly allows aws-marketplace:Subscribe on Resource:*."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam")
        policy_name = "marketplace_subscribe_wildcard"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "aws-marketplace:Subscribe",
                    "Resource": "*",
                },
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                f"{CHECK_MODULE_PATH}.iam_client",
                new=IAM(aws_provider),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_marketplace_subscription_access_least_privilege.bedrock_marketplace_subscription_access_least_privilege import (
                    bedrock_marketplace_subscription_access_least_privilege,
                )

                check = bedrock_marketplace_subscription_access_least_privilege()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"IAM policy {policy_name} allows aws-marketplace:Subscribe on all resources."
                )
                assert result[0].resource_id == policy_name
                assert result[0].resource_arn == arn
                assert result[0].region == "us-east-1"

    @mock_aws
    def test_policy_allows_marketplace_wildcard_action_on_all_resources(self):
        """FAIL: Policy allows aws-marketplace:* on Resource:*."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam")
        policy_name = "marketplace_all_actions"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "aws-marketplace:*",
                    "Resource": "*",
                },
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                f"{CHECK_MODULE_PATH}.iam_client",
                new=IAM(aws_provider),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_marketplace_subscription_access_least_privilege.bedrock_marketplace_subscription_access_least_privilege import (
                    bedrock_marketplace_subscription_access_least_privilege,
                )

                check = bedrock_marketplace_subscription_access_least_privilege()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"IAM policy {policy_name} allows aws-marketplace:Subscribe on all resources."
                )
                assert result[0].resource_id == policy_name
                assert result[0].resource_arn == arn
                assert result[0].region == "us-east-1"

    @mock_aws
    def test_policy_allows_full_wildcard_on_all_resources(self):
        """FAIL: Policy allows * (all actions) on Resource:*."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam")
        policy_name = "full_admin_access"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                },
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                f"{CHECK_MODULE_PATH}.iam_client",
                new=IAM(aws_provider),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_marketplace_subscription_access_least_privilege.bedrock_marketplace_subscription_access_least_privilege import (
                    bedrock_marketplace_subscription_access_least_privilege,
                )

                check = bedrock_marketplace_subscription_access_least_privilege()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"IAM policy {policy_name} allows aws-marketplace:Subscribe on all resources."
                )
                assert result[0].resource_id == policy_name
                assert result[0].resource_arn == arn
                assert result[0].region == "us-east-1"

    @mock_aws
    def test_policy_allows_marketplace_subscribe_on_specific_resource(self):
        """PASS: Policy allows aws-marketplace:Subscribe on a specific resource ARN."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam")
        policy_name = "marketplace_subscribe_scoped"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "aws-marketplace:Subscribe",
                    "Resource": "arn:aws:aws-marketplace::123456789012:product/example-product-id",
                },
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                f"{CHECK_MODULE_PATH}.iam_client",
                new=IAM(aws_provider),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_marketplace_subscription_access_least_privilege.bedrock_marketplace_subscription_access_least_privilege import (
                    bedrock_marketplace_subscription_access_least_privilege,
                )

                check = bedrock_marketplace_subscription_access_least_privilege()
                result = check.execute()
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"IAM policy {policy_name} does not allow aws-marketplace:Subscribe on all resources."
                )
                assert result[0].resource_id == policy_name
                assert result[0].resource_arn == arn
                assert result[0].region == "us-east-1"

    @mock_aws
    def test_policy_unrelated_action_on_all_resources(self):
        """PASS: Policy allows an unrelated action on Resource:*."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam")
        policy_name = "ec2_full_access"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "ec2:*",
                    "Resource": "*",
                },
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                f"{CHECK_MODULE_PATH}.iam_client",
                new=IAM(aws_provider),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_marketplace_subscription_access_least_privilege.bedrock_marketplace_subscription_access_least_privilege import (
                    bedrock_marketplace_subscription_access_least_privilege,
                )

                check = bedrock_marketplace_subscription_access_least_privilege()
                result = check.execute()
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"IAM policy {policy_name} does not allow aws-marketplace:Subscribe on all resources."
                )
                assert result[0].resource_id == policy_name
                assert result[0].resource_arn == arn
                assert result[0].region == "us-east-1"

    @mock_aws
    def test_policy_marketplace_subscribe_denied(self):
        """PASS: Policy allows aws-marketplace:Subscribe on Resource:* but a Deny overrides it."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam")
        policy_name = "marketplace_subscribe_denied"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "aws-marketplace:Subscribe",
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "Action": "aws-marketplace:Subscribe",
                    "Resource": "*",
                },
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                f"{CHECK_MODULE_PATH}.iam_client",
                new=IAM(aws_provider),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_marketplace_subscription_access_least_privilege.bedrock_marketplace_subscription_access_least_privilege import (
                    bedrock_marketplace_subscription_access_least_privilege,
                )

                check = bedrock_marketplace_subscription_access_least_privilege()
                result = check.execute()
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"IAM policy {policy_name} does not allow aws-marketplace:Subscribe on all resources."
                )
                assert result[0].resource_id == policy_name
                assert result[0].resource_arn == arn
                assert result[0].region == "us-east-1"

    @mock_aws
    def test_policy_marketplace_subscribe_in_action_list(self):
        """FAIL: Policy allows aws-marketplace:Subscribe among other actions on Resource:*."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam")
        policy_name = "mixed_actions"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:DescribeInstances",
                        "aws-marketplace:Subscribe",
                    ],
                    "Resource": "*",
                },
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                f"{CHECK_MODULE_PATH}.iam_client",
                new=IAM(aws_provider),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_marketplace_subscription_access_least_privilege.bedrock_marketplace_subscription_access_least_privilege import (
                    bedrock_marketplace_subscription_access_least_privilege,
                )

                check = bedrock_marketplace_subscription_access_least_privilege()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"IAM policy {policy_name} allows aws-marketplace:Subscribe on all resources."
                )
                assert result[0].resource_id == policy_name
                assert result[0].resource_arn == arn
                assert result[0].region == "us-east-1"

    @mock_aws
    def test_no_custom_policies(self):
        """No findings when there are no custom IAM policies."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                f"{CHECK_MODULE_PATH}.iam_client",
                new=IAM(aws_provider),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_marketplace_subscription_access_least_privilege.bedrock_marketplace_subscription_access_least_privilege import (
                    bedrock_marketplace_subscription_access_least_privilege,
                )

                check = bedrock_marketplace_subscription_access_least_privilege()
                result = check.execute()
                assert len(result) == 0

    @mock_aws
    def test_policy_resource_list_containing_wildcard(self):
        """FAIL: Policy allows aws-marketplace:Subscribe with Resource list containing *."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam")
        policy_name = "resource_list_with_wildcard"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "aws-marketplace:Subscribe",
                    "Resource": [
                        "arn:aws:aws-marketplace::123456789012:product/example-product-id",
                        "*",
                    ],
                },
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                f"{CHECK_MODULE_PATH}.iam_client",
                new=IAM(aws_provider),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_marketplace_subscription_access_least_privilege.bedrock_marketplace_subscription_access_least_privilege import (
                    bedrock_marketplace_subscription_access_least_privilege,
                )

                check = bedrock_marketplace_subscription_access_least_privilege()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"IAM policy {policy_name} allows aws-marketplace:Subscribe on all resources."
                )
                assert result[0].resource_id == policy_name
                assert result[0].resource_arn == arn
                assert result[0].region == "us-east-1"

    @mock_aws
    def test_policy_case_insensitive_action_matching(self):
        """FAIL: Policy with mixed-case action still matches aws-marketplace:Subscribe."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam")
        policy_name = "mixed_case_subscribe"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "AWS-Marketplace:SUBSCRIBE",
                    "Resource": "*",
                },
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                f"{CHECK_MODULE_PATH}.iam_client",
                new=IAM(aws_provider),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_marketplace_subscription_access_least_privilege.bedrock_marketplace_subscription_access_least_privilege import (
                    bedrock_marketplace_subscription_access_least_privilege,
                )

                check = bedrock_marketplace_subscription_access_least_privilege()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"IAM policy {policy_name} allows aws-marketplace:Subscribe on all resources."
                )
                assert result[0].resource_id == policy_name
                assert result[0].resource_arn == arn
                assert result[0].region == "us-east-1"

    @mock_aws
    def test_policy_deny_unrelated_action_does_not_override_allow(self):
        """FAIL: Deny for a different action does not override the Allow for Subscribe."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam")
        policy_name = "deny_unrelated_action"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "aws-marketplace:Subscribe",
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "Action": "ec2:TerminateInstances",
                    "Resource": "*",
                },
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                f"{CHECK_MODULE_PATH}.iam_client",
                new=IAM(aws_provider),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_marketplace_subscription_access_least_privilege.bedrock_marketplace_subscription_access_least_privilege import (
                    bedrock_marketplace_subscription_access_least_privilege,
                )

                check = bedrock_marketplace_subscription_access_least_privilege()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"IAM policy {policy_name} allows aws-marketplace:Subscribe on all resources."
                )
                assert result[0].resource_id == policy_name
                assert result[0].resource_arn == arn
                assert result[0].region == "us-east-1"

    @mock_aws
    def test_policy_resource_list_without_wildcard(self):
        """PASS: Policy allows aws-marketplace:Subscribe on specific resources only (list without *)."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam")
        policy_name = "scoped_resource_list"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "aws-marketplace:Subscribe",
                    "Resource": [
                        "arn:aws:aws-marketplace::123456789012:product/product-1",
                        "arn:aws:aws-marketplace::123456789012:product/product-2",
                    ],
                },
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                f"{CHECK_MODULE_PATH}.iam_client",
                new=IAM(aws_provider),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_marketplace_subscription_access_least_privilege.bedrock_marketplace_subscription_access_least_privilege import (
                    bedrock_marketplace_subscription_access_least_privilege,
                )

                check = bedrock_marketplace_subscription_access_least_privilege()
                result = check.execute()
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"IAM policy {policy_name} does not allow aws-marketplace:Subscribe on all resources."
                )
                assert result[0].resource_id == policy_name
                assert result[0].resource_arn == arn
                assert result[0].region == "us-east-1"
