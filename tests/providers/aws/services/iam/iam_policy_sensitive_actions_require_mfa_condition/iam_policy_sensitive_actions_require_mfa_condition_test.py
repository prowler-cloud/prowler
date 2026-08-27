from json import dumps
from re import search
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_iam_policy_sensitive_actions_require_mfa_condition:
    @mock_aws
    def test_pass_no_sensitive_actions(self):
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::example-bucket/*",
                },
            ],
        }
        policy_arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition import (
                iam_policy_sensitive_actions_require_mfa_condition,
            )

            check = iam_policy_sensitive_actions_require_mfa_condition()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == policy_name
            assert result[0].resource_arn == policy_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].status_extended
                == f"Custom Policy {policy_arn} does not allow sensitive actions without requiring MFA."
            )

    @mock_aws
    def test_fail_passrole_without_mfa(self):
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/ecs",
                },
            ],
        }
        policy_arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition import (
                iam_policy_sensitive_actions_require_mfa_condition,
            )

            check = iam_policy_sensitive_actions_require_mfa_condition()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == policy_name
            assert result[0].resource_arn == policy_arn
            assert search(
                f"Custom Policy {policy_arn} allows the following sensitive actions without requiring MFA: ",
                result[0].status_extended,
            )
            assert search("iam:passrole", result[0].status_extended)

    @mock_aws
    def test_pass_passrole_with_mfa_bool_condition(self):
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/ecs",
                    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                },
            ],
        }
        policy_arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition import (
                iam_policy_sensitive_actions_require_mfa_condition,
            )

            check = iam_policy_sensitive_actions_require_mfa_condition()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_arn == policy_arn

    @mock_aws
    def test_pass_assumerole_with_lowercase_mfa_condition_key(self):
        # AWS condition context key names are not case-sensitive, so a
        # policy author could write aws:multifactorauthpresent in any case.
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": "*",
                    "Condition": {
                        "BoolIfExists": {"aws:multifactorauthpresent": "true"}
                    },
                },
            ],
        }
        policy_arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition import (
                iam_policy_sensitive_actions_require_mfa_condition,
            )

            check = iam_policy_sensitive_actions_require_mfa_condition()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_arn == policy_arn

    @mock_aws
    def test_fail_multiple_sensitive_actions_without_mfa(self):
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["iam:CreateAccessKey", "iam:AttachUserPolicy"],
                    "Resource": "*",
                },
            ],
        }
        policy_arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition import (
                iam_policy_sensitive_actions_require_mfa_condition,
            )

            check = iam_policy_sensitive_actions_require_mfa_condition()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_arn == policy_arn
            assert search("iam:createaccesskey", result[0].status_extended)
            assert search("iam:attachuserpolicy", result[0].status_extended)

    @mock_aws
    def test_deny_statement_ignored(self):
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"},
            ],
        }
        policy_arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition import (
                iam_policy_sensitive_actions_require_mfa_condition,
            )

            check = iam_policy_sensitive_actions_require_mfa_condition()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_arn == policy_arn

    @mock_aws
    def test_unattached_policy_skipped_when_scan_unused_services_disabled(self):
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        policy_name = "unattached_policy"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"},
            ],
        }
        iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], scan_unused_services=False
        )
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition import (
                iam_policy_sensitive_actions_require_mfa_condition,
            )

            check = iam_policy_sensitive_actions_require_mfa_condition()
            result = check.execute()
            assert result == []

    @mock_aws
    def test_attached_policy_fails_when_scan_unused_services_disabled(self):
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        user_name = "test_user_mfa_condition"
        policy_name = "attached_policy"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"},
            ],
        }
        policy_arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]
        iam_client.create_user(UserName=user_name)
        iam_client.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], scan_unused_services=False
        )
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition import (
                iam_policy_sensitive_actions_require_mfa_condition,
            )

            check = iam_policy_sensitive_actions_require_mfa_condition()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_arn == policy_arn

    @mock_aws
    def test_no_resources(self):
        """No customer-managed policies means no findings, not a spurious FAIL."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition import (
                iam_policy_sensitive_actions_require_mfa_condition,
            )

            check = iam_policy_sensitive_actions_require_mfa_condition()
            result = check.execute()
            assert result == []

    @mock_aws
    def test_fail_mfa_condition_explicitly_false(self):
        """A Condition setting aws:MultiFactorAuthPresent to false is not a
        passing MFA requirement; it must still be flagged as unprotected."""
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/ecs",
                    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}},
                },
            ],
        }
        policy_arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition import (
                iam_policy_sensitive_actions_require_mfa_condition,
            )

            check = iam_policy_sensitive_actions_require_mfa_condition()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_arn == policy_arn

    @mock_aws
    def test_fail_mfa_condition_wrong_operator(self):
        """StringEquals is not a valid operator for the Boolean
        aws:MultiFactorAuthPresent key; it must not satisfy the check."""
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/ecs",
                    "Condition": {
                        "StringEquals": {"aws:MultiFactorAuthPresent": "true"}
                    },
                },
            ],
        }
        policy_arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition import (
                iam_policy_sensitive_actions_require_mfa_condition,
            )

            check = iam_policy_sensitive_actions_require_mfa_condition()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_arn == policy_arn

    @mock_aws
    def test_fail_iam_wildcard_without_mfa(self):
        """iam:* covers the sensitive actions and must be expanded, not
        exact-matched, to be caught."""
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "iam:*", "Resource": "*"},
            ],
        }
        policy_arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition import (
                iam_policy_sensitive_actions_require_mfa_condition,
            )

            check = iam_policy_sensitive_actions_require_mfa_condition()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_arn == policy_arn
            assert search("iam:passrole", result[0].status_extended)
            assert search("iam:createaccesskey", result[0].status_extended)

    @mock_aws
    def test_fail_notaction_without_mfa(self):
        """A NotAction excluding an unrelated service implicitly grants the
        sensitive actions and must still be caught."""
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"},
            ],
        }
        policy_arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_policy_sensitive_actions_require_mfa_condition.iam_policy_sensitive_actions_require_mfa_condition import (
                iam_policy_sensitive_actions_require_mfa_condition,
            )

            check = iam_policy_sensitive_actions_require_mfa_condition()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_arn == policy_arn
            assert search("iam:passrole", result[0].status_extended)
            assert result[0].resource_arn == policy_arn
