from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_iam_no_root_access_key_test:
    @mock_aws
    def test_iam_root_no_access_keys(self):
        iam_client = client("iam")
        user = "test"
        iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_no_root_access_key.iam_no_root_access_key.iam_client",
                new=IAM(aws_provider),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_no_root_access_key.iam_no_root_access_key import (
                    iam_no_root_access_key,
                )

                service_client.credential_report[0]["user"] = "<root_account>"
                service_client.credential_report[0][
                    "arn"
                ] = "arn:aws:iam::123456789012:user/<root_account>"
                service_client.credential_report[0]["access_key_1_active"] = "false"
                service_client.credential_report[0]["access_key_2_active"] = "false"
                check = iam_no_root_access_key()
                result = check.execute()

                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "Root account does not have access keys."
                )
                assert result[0].resource_id == "<root_account>"
                assert (
                    result[0].resource_arn
                    == "arn:aws:iam::123456789012:user/<root_account>"
                )

    @mock_aws
    def test_iam_root_access_key_1(self):
        iam_client = client("iam")
        user = "test"
        iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_no_root_access_key.iam_no_root_access_key.iam_client",
                new=IAM(aws_provider),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_no_root_access_key.iam_no_root_access_key import (
                    iam_no_root_access_key,
                )

                service_client.credential_report[0]["user"] = "<root_account>"
                service_client.credential_report[0][
                    "arn"
                ] = "arn:aws:iam::123456789012:user/<root_account>"
                service_client.credential_report[0]["access_key_1_active"] = "true"
                service_client.credential_report[0]["access_key_2_active"] = "false"
                check = iam_no_root_access_key()
                result = check.execute()

                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Root account has one active access key."
                )
                assert result[0].resource_id == "<root_account>"
                assert (
                    result[0].resource_arn
                    == "arn:aws:iam::123456789012:user/<root_account>"
                )

    @mock_aws
    def test_iam_root_access_key_2(self):
        iam_client = client("iam")
        user = "test"
        iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_no_root_access_key.iam_no_root_access_key.iam_client",
                new=IAM(aws_provider),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_no_root_access_key.iam_no_root_access_key import (
                    iam_no_root_access_key,
                )

                service_client.credential_report[0]["user"] = "<root_account>"
                service_client.credential_report[0][
                    "arn"
                ] = "arn:aws:iam::123456789012:user/<root_account>"
                service_client.credential_report[0]["access_key_1_active"] = "false"
                service_client.credential_report[0]["access_key_2_active"] = "true"
                check = iam_no_root_access_key()
                result = check.execute()

                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Root account has one active access key."
                )
                assert result[0].resource_id == "<root_account>"
                assert (
                    result[0].resource_arn
                    == "arn:aws:iam::123456789012:user/<root_account>"
                )

    @mock_aws
    def test_iam_root_both_access_keys(self):
        iam_client = client("iam")
        user = "test"
        iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_no_root_access_key.iam_no_root_access_key.iam_client",
                new=IAM(aws_provider),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_no_root_access_key.iam_no_root_access_key import (
                    iam_no_root_access_key,
                )

                service_client.credential_report[0]["user"] = "<root_account>"
                service_client.credential_report[0][
                    "arn"
                ] = "arn:aws:iam::123456789012:user/<root_account>"
                service_client.credential_report[0]["access_key_1_active"] = "true"
                service_client.credential_report[0]["access_key_2_active"] = "true"
                check = iam_no_root_access_key()
                result = check.execute()

                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Root account has two active access keys."
                )
                assert result[0].resource_id == "<root_account>"
                assert (
                    result[0].resource_arn
                    == "arn:aws:iam::123456789012:user/<root_account>"
                )
