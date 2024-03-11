from json import dumps
from re import search
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_iam_no_custom_policy_permissive_role_assumption:
    @mock_aws
    def test_policy_allows_permissive_role_assumption_wildcard(self):
        iam_client = client("iam")
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "sts:*", "Resource": "*"},
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_no_custom_policy_permissive_role_assumption.iam_no_custom_policy_permissive_role_assumption.iam_client",
                new=IAM(aws_provider),
            ):
                from prowler.providers.aws.services.iam.iam_no_custom_policy_permissive_role_assumption.iam_no_custom_policy_permissive_role_assumption import (
                    iam_no_custom_policy_permissive_role_assumption,
                )

                check = iam_no_custom_policy_permissive_role_assumption()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert search(
                    f"Custom Policy {policy_name} allows permissive STS Role assumption",
                    result[0].status_extended,
                )
                assert result[0].resource_arn == arn
                assert result[0].resource_id == policy_name

    @mock_aws
    def test_policy_allows_permissive_role_assumption_no_wilcard(self):
        iam_client = client("iam")
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"},
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_no_custom_policy_permissive_role_assumption.iam_no_custom_policy_permissive_role_assumption.iam_client",
                new=IAM(aws_provider),
            ):
                from prowler.providers.aws.services.iam.iam_no_custom_policy_permissive_role_assumption.iam_no_custom_policy_permissive_role_assumption import (
                    iam_no_custom_policy_permissive_role_assumption,
                )

                check = iam_no_custom_policy_permissive_role_assumption()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert search(
                    f"Custom Policy {policy_name} allows permissive STS Role assumption",
                    result[0].status_extended,
                )
                assert result[0].resource_arn == arn
                assert result[0].resource_id == policy_name

    @mock_aws
    def test_policy_assume_role_not_allow_permissive_role_assumption(self):
        iam_client = client("iam")
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": "arn:aws:iam::123456789012:user/JohnDoe",
                },
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_no_custom_policy_permissive_role_assumption.iam_no_custom_policy_permissive_role_assumption.iam_client",
                new=IAM(aws_provider),
            ):
                from prowler.providers.aws.services.iam.iam_no_custom_policy_permissive_role_assumption.iam_no_custom_policy_permissive_role_assumption import (
                    iam_no_custom_policy_permissive_role_assumption,
                )

                check = iam_no_custom_policy_permissive_role_assumption()
                result = check.execute()
                assert result[0].status == "PASS"
                assert search(
                    f"Custom Policy {policy_name} does not allow permissive STS Role assumption",
                    result[0].status_extended,
                )
                assert result[0].resource_arn == arn
                assert result[0].resource_id == policy_name

    @mock_aws
    def test_policy_not_allow_permissive_role_assumption(self):
        iam_client = client("iam")
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "logs:CreateLogGroup", "Resource": "*"},
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_no_custom_policy_permissive_role_assumption.iam_no_custom_policy_permissive_role_assumption.iam_client",
                new=IAM(aws_provider),
            ):
                from prowler.providers.aws.services.iam.iam_no_custom_policy_permissive_role_assumption.iam_no_custom_policy_permissive_role_assumption import (
                    iam_no_custom_policy_permissive_role_assumption,
                )

                check = iam_no_custom_policy_permissive_role_assumption()
                result = check.execute()
                assert result[0].status == "PASS"
                assert search(
                    f"Custom Policy {policy_name} does not allow permissive STS Role assumption",
                    result[0].status_extended,
                )
                assert result[0].resource_arn == arn
                assert result[0].resource_id == policy_name

    @mock_aws
    def test_policy_permissive_and_not_permissive(self):
        iam_client = client("iam")
        policy_name_non_permissive = "policy1"
        policy_document_non_permissive = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "logs:*", "Resource": "*"},
            ],
        }
        policy_name_permissive = "policy2"
        policy_document_permissive = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"},
            ],
        }
        arn_non_permissive = iam_client.create_policy(
            PolicyName=policy_name_non_permissive,
            PolicyDocument=dumps(policy_document_non_permissive),
        )["Policy"]["Arn"]
        arn_permissive = iam_client.create_policy(
            PolicyName=policy_name_permissive,
            PolicyDocument=dumps(policy_document_permissive),
        )["Policy"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_no_custom_policy_permissive_role_assumption.iam_no_custom_policy_permissive_role_assumption.iam_client",
                new=IAM(aws_provider),
            ):
                from prowler.providers.aws.services.iam.iam_no_custom_policy_permissive_role_assumption.iam_no_custom_policy_permissive_role_assumption import (
                    iam_no_custom_policy_permissive_role_assumption,
                )

                check = iam_no_custom_policy_permissive_role_assumption()
                result = check.execute()
                assert len(result) == 2
                assert result[0].status == "PASS"
                assert result[0].resource_arn == arn_non_permissive
                assert search(
                    f"Policy {policy_name_non_permissive} does not allow permissive STS Role assumption",
                    result[0].status_extended,
                )
                assert result[0].resource_id == policy_name_non_permissive
                assert result[1].status == "FAIL"
                assert result[1].resource_arn == arn_permissive
                assert search(
                    f"Policy {policy_name_permissive} allows permissive STS Role assumption",
                    result[1].status_extended,
                )
                assert result[1].resource_id == policy_name_permissive
