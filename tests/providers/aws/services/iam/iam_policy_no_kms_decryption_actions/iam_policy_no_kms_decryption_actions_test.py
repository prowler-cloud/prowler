from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.iam.iam_service import IAM
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_iam_policy_no_kms_decryption_actions:
    @mock_aws
    def test_no_policies(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_no_kms_decryption_actions.iam_policy_no_kms_decryption_actions.iam_client",
                new=IAM(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_policy_no_kms_decryption_actions.iam_policy_no_kms_decryption_actions import (
                    iam_policy_no_kms_decryption_actions,
                )

                check = iam_policy_no_kms_decryption_actions()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_iam_policy_no_kms_actions(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam")
        policy_name = "no_kms_actions"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Deny", "Action": "kms:Decrypt", "Resource": "*"},
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
                "prowler.providers.aws.services.iam.iam_policy_no_kms_decryption_actions.iam_policy_no_kms_decryption_actions.iam_client",
                new=IAM(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_policy_no_kms_decryption_actions.iam_policy_no_kms_decryption_actions import (
                    iam_policy_no_kms_decryption_actions,
                )

                check = iam_policy_no_kms_decryption_actions()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Custom Policy {policy_name} does not allow kms:Decrypt or kms:ReEncryptFrom privileges on all resources."
                )
                assert result[0].resource_id == policy_name
                assert result[0].resource_arn == arn
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []

    @mock_aws
    def test_iam_policy_allows_kms_decrypt(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam")
        policy_name = "allows_kms_decrypt"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"},
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
                "prowler.providers.aws.services.iam.iam_policy_no_kms_decryption_actions.iam_policy_no_kms_decryption_actions.iam_client",
                new=IAM(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_policy_no_kms_decryption_actions.iam_policy_no_kms_decryption_actions import (
                    iam_policy_no_kms_decryption_actions,
                )

                check = iam_policy_no_kms_decryption_actions()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"Custom Policy {policy_name} does allow kms:Decrypt or kms:ReEncryptFrom privileges on all resources."
                )
                assert result[0].resource_id == policy_name
                assert result[0].resource_arn == arn
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []

    @mock_aws
    def test_iam_policy_allows_kms_reencrypt_from(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam")
        policy_name = "allows_kms_reencrypt_from"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "kms:ReEncryptFrom", "Resource": "*"},
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
                "prowler.providers.aws.services.iam.iam_policy_no_kms_decryption_actions.iam_policy_no_kms_decryption_actions.iam_client",
                new=IAM(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_policy_no_kms_decryption_actions.iam_policy_no_kms_decryption_actions import (
                    iam_policy_no_kms_decryption_actions,
                )

                check = iam_policy_no_kms_decryption_actions()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"Custom Policy {policy_name} does allow kms:Decrypt or kms:ReEncryptFrom privileges on all resources."
                )
                assert result[0].resource_id == policy_name
                assert result[0].resource_arn == arn
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []

    @mock_aws
    def test_iam_policy_allows_kms_decrypt_on_specific_resource(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam")
        policy_name = "allows_kms_decrypt_specific_resource"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "kms:Decrypt",
                    "Resource": "arn:aws:kms:us-east-1:123456789012:key/1234abcd",
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
                "prowler.providers.aws.services.iam.iam_policy_no_kms_decryption_actions.iam_policy_no_kms_decryption_actions.iam_client",
                new=IAM(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_policy_no_kms_decryption_actions.iam_policy_no_kms_decryption_actions import (
                    iam_policy_no_kms_decryption_actions,
                )

                check = iam_policy_no_kms_decryption_actions()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Custom Policy {policy_name} does not allow kms:Decrypt or kms:ReEncryptFrom privileges on all resources."
                )
                assert result[0].resource_id == policy_name
                assert result[0].resource_arn == arn
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []

    @mock_aws
    def test_iam_policy_allows_kms_reencrypt_from_on_specific_resource(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam")
        policy_name = "allows_kms_decrypt_specific_resource"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "kms:ReEncryptFrom",
                    "Resource": "arn:aws:kms:us-east-1:123456789012:key/1234abcd",
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
                "prowler.providers.aws.services.iam.iam_policy_no_kms_decryption_actions.iam_policy_no_kms_decryption_actions.iam_client",
                new=IAM(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_policy_no_kms_decryption_actions.iam_policy_no_kms_decryption_actions import (
                    iam_policy_no_kms_decryption_actions,
                )

                check = iam_policy_no_kms_decryption_actions()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Custom Policy {policy_name} does not allow kms:Decrypt or kms:ReEncryptFrom privileges on all resources."
                )
                assert result[0].resource_id == policy_name
                assert result[0].resource_arn == arn
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []

    @mock_aws
    def test_iam_policy_allows_both_kms_actions(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam")
        policy_name = "allows_both_kms_actions"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["kms:Decrypt", "kms:ReEncryptFrom"],
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
                "prowler.providers.aws.services.iam.iam_policy_no_kms_decryption_actions.iam_policy_no_kms_decryption_actions.iam_client",
                new=IAM(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_policy_no_kms_decryption_actions.iam_policy_no_kms_decryption_actions import (
                    iam_policy_no_kms_decryption_actions,
                )

                check = iam_policy_no_kms_decryption_actions()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"Custom Policy {policy_name} does allow kms:Decrypt or kms:ReEncryptFrom privileges on all resources."
                )
                assert result[0].resource_id == policy_name
                assert result[0].resource_arn == arn
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []

    @mock_aws
    def test_iam_policy_unrelated_actions_policy(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = client("iam")
        policy_name = "unrelated_actions_policy"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"},
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
                "prowler.providers.aws.services.iam.iam_policy_no_kms_decryption_actions.iam_policy_no_kms_decryption_actions.iam_client",
                new=IAM(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_policy_no_kms_decryption_actions.iam_policy_no_kms_decryption_actions import (
                    iam_policy_no_kms_decryption_actions,
                )

                check = iam_policy_no_kms_decryption_actions()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Custom Policy {policy_name} does not allow kms:Decrypt or kms:ReEncryptFrom privileges on all resources."
                )
                assert result[0].resource_id == policy_name
                assert result[0].resource_arn == arn
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []
