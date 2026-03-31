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

CHECK_MODULE_PATH = "prowler.providers.aws.services.iam.iam_inline_policy_no_wildcard_marketplace_subscribe.iam_inline_policy_no_wildcard_marketplace_subscribe"


class Test_iam_inline_policy_no_wildcard_marketplace_subscribe:
    @mock_aws
    def test_inline_policy_allows_marketplace_subscribe_on_all_resources(self):
        """FAIL: Inline policy allows aws-marketplace:Subscribe on Resource:*."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        role_name = "test_role"
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(ADMINISTRATOR_ROLE_ASSUME_ROLE_POLICY),
        )["Role"]["Arn"]

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
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=dumps(policy_document),
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_wildcard_marketplace_subscribe.iam_inline_policy_no_wildcard_marketplace_subscribe import (
                iam_inline_policy_no_wildcard_marketplace_subscribe,
            )

            check = iam_inline_policy_no_wildcard_marketplace_subscribe()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Inline policy {policy_name} attached to role {role_name} allows 'aws-marketplace:Subscribe' on all resources."
            )
            assert result[0].resource_id == f"{role_name}/{policy_name}"
            assert result[0].resource_arn == role_arn
            assert result[0].region == "eu-west-1"

    @mock_aws
    def test_inline_policy_allows_marketplace_wildcard_action(self):
        """FAIL: Inline policy allows aws-marketplace:* on Resource:*."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        role_name = "test_role"
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(ADMINISTRATOR_ROLE_ASSUME_ROLE_POLICY),
        )["Role"]["Arn"]

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
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=dumps(policy_document),
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_wildcard_marketplace_subscribe.iam_inline_policy_no_wildcard_marketplace_subscribe import (
                iam_inline_policy_no_wildcard_marketplace_subscribe,
            )

            check = iam_inline_policy_no_wildcard_marketplace_subscribe()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Inline policy {policy_name} attached to role {role_name} allows 'aws-marketplace:Subscribe' on all resources."
            )
            assert result[0].resource_id == f"{role_name}/{policy_name}"
            assert result[0].resource_arn == role_arn
            assert result[0].region == "eu-west-1"

    @mock_aws
    def test_inline_policy_scoped_resource(self):
        """PASS: Inline policy allows aws-marketplace:Subscribe on a specific resource."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        role_name = "test_role"
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(ADMINISTRATOR_ROLE_ASSUME_ROLE_POLICY),
        )["Role"]["Arn"]

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
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=dumps(policy_document),
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_wildcard_marketplace_subscribe.iam_inline_policy_no_wildcard_marketplace_subscribe import (
                iam_inline_policy_no_wildcard_marketplace_subscribe,
            )

            check = iam_inline_policy_no_wildcard_marketplace_subscribe()
            result = check.execute()
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Inline policy {policy_name} attached to role {role_name} does not allow 'aws-marketplace:Subscribe' on all resources."
            )
            assert result[0].resource_id == f"{role_name}/{policy_name}"
            assert result[0].resource_arn == role_arn
            assert result[0].region == "eu-west-1"

    @mock_aws
    def test_inline_policy_unrelated_action(self):
        """PASS: Inline policy allows an unrelated action on Resource:*."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        role_name = "test_role"
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(ADMINISTRATOR_ROLE_ASSUME_ROLE_POLICY),
        )["Role"]["Arn"]

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
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=dumps(policy_document),
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_wildcard_marketplace_subscribe.iam_inline_policy_no_wildcard_marketplace_subscribe import (
                iam_inline_policy_no_wildcard_marketplace_subscribe,
            )

            check = iam_inline_policy_no_wildcard_marketplace_subscribe()
            result = check.execute()
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Inline policy {policy_name} attached to role {role_name} does not allow 'aws-marketplace:Subscribe' on all resources."
            )
            assert result[0].resource_id == f"{role_name}/{policy_name}"
            assert result[0].resource_arn == role_arn
            assert result[0].region == "eu-west-1"

    @mock_aws
    def test_inline_policy_deny_overrides_allow(self):
        """PASS: Allow + Deny on * for same action — Deny wins."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        role_name = "test_role"
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(ADMINISTRATOR_ROLE_ASSUME_ROLE_POLICY),
        )["Role"]["Arn"]

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
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=dumps(policy_document),
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_wildcard_marketplace_subscribe.iam_inline_policy_no_wildcard_marketplace_subscribe import (
                iam_inline_policy_no_wildcard_marketplace_subscribe,
            )

            check = iam_inline_policy_no_wildcard_marketplace_subscribe()
            result = check.execute()
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Inline policy {policy_name} attached to role {role_name} does not allow 'aws-marketplace:Subscribe' on all resources."
            )
            assert result[0].resource_id == f"{role_name}/{policy_name}"
            assert result[0].resource_arn == role_arn
            assert result[0].region == "eu-west-1"

    @mock_aws
    def test_inline_policy_deny_specific_resource_does_not_override(self):
        """FAIL: Deny on specific resource does not negate Allow on *."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        role_name = "test_role"
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(ADMINISTRATOR_ROLE_ASSUME_ROLE_POLICY),
        )["Role"]["Arn"]

        policy_name = "deny_specific_only"
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
                    "Resource": "arn:aws:aws-marketplace::123456789012:product/blocked",
                },
            ],
        }
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=dumps(policy_document),
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_wildcard_marketplace_subscribe.iam_inline_policy_no_wildcard_marketplace_subscribe import (
                iam_inline_policy_no_wildcard_marketplace_subscribe,
            )

            check = iam_inline_policy_no_wildcard_marketplace_subscribe()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Inline policy {policy_name} attached to role {role_name} allows 'aws-marketplace:Subscribe' on all resources."
            )
            assert result[0].resource_id == f"{role_name}/{policy_name}"
            assert result[0].resource_arn == role_arn
            assert result[0].region == "eu-west-1"

    @mock_aws
    def test_no_inline_policies(self):
        """No findings when there are no inline policies."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_wildcard_marketplace_subscribe.iam_inline_policy_no_wildcard_marketplace_subscribe import (
                iam_inline_policy_no_wildcard_marketplace_subscribe,
            )

            check = iam_inline_policy_no_wildcard_marketplace_subscribe()
            result = check.execute()
            assert len(result) == 0
