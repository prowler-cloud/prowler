import datetime
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


class Test_iam_user_accesskey_unused_test:
    @mock_aws
    def test_user_no_access_keys(self):
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], audit_config={"max_unused_access_keys_days": 45}
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_user_accesskey_unused.iam_user_accesskey_unused.iam_client",
                new=IAM(aws_provider),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_user_accesskey_unused.iam_user_accesskey_unused import (
                    iam_user_accesskey_unused,
                )

                service_client.credential_report[0][
                    "access_key_1_last_rotated"
                ] == "N/A"
                service_client.credential_report[0][
                    "access_key_2_last_rotated"
                ] == "N/A"

                check = iam_user_accesskey_unused()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"User {user} does not have access keys."
                )
                assert result[0].resource_id == user
                assert result[0].resource_arn == arn
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_user_access_key_1_not_used(self):
        credentials_last_rotated = (
            datetime.datetime.now() - datetime.timedelta(days=100)
        ).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], audit_config={"max_unused_access_keys_days": 45}
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_user_accesskey_unused.iam_user_accesskey_unused.iam_client",
                new=IAM(aws_provider),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_user_accesskey_unused.iam_user_accesskey_unused import (
                    iam_user_accesskey_unused,
                )

                service_client.credential_report[0]["access_key_1_active"] = "true"
                service_client.credential_report[0][
                    "access_key_1_last_used_date"
                ] = credentials_last_rotated

                check = iam_user_accesskey_unused()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"User {user} has not used access key 1 in the last 45 days (100 days)."
                )
                assert result[0].resource_id == user + "/AccessKey1"
                assert result[0].resource_arn == arn
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_user_access_key_2_not_used(self):
        credentials_last_rotated = (
            datetime.datetime.now() - datetime.timedelta(days=100)
        ).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], audit_config={"max_unused_access_keys_days": 45}
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_user_accesskey_unused.iam_user_accesskey_unused.iam_client",
                new=IAM(aws_provider),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_user_accesskey_unused.iam_user_accesskey_unused import (
                    iam_user_accesskey_unused,
                )

                service_client.credential_report[0]["access_key_2_active"] = "true"
                service_client.credential_report[0][
                    "access_key_2_last_used_date"
                ] = credentials_last_rotated

                check = iam_user_accesskey_unused()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"User {user} has not used access key 2 in the last 45 days (100 days)."
                )
                assert result[0].resource_id == user + "/AccessKey2"
                assert result[0].resource_arn == arn
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_user_both_access_keys_not_used(self):
        credentials_last_rotated = (
            datetime.datetime.now() - datetime.timedelta(days=100)
        ).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], audit_config={"max_unused_access_keys_days": 45}
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_user_accesskey_unused.iam_user_accesskey_unused.iam_client",
                new=IAM(aws_provider),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_user_accesskey_unused.iam_user_accesskey_unused import (
                    iam_user_accesskey_unused,
                )

                service_client.credential_report[0]["access_key_1_active"] = "true"
                service_client.credential_report[0][
                    "access_key_1_last_used_date"
                ] = credentials_last_rotated

                service_client.credential_report[0]["access_key_2_active"] = "true"
                service_client.credential_report[0][
                    "access_key_2_last_used_date"
                ] = credentials_last_rotated

                check = iam_user_accesskey_unused()
                result = check.execute()
                assert len(result) == 2
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"User {user} has not used access key 1 in the last 45 days (100 days)."
                )
                assert result[0].resource_id == user + "/AccessKey1"
                assert result[0].resource_arn == arn
                assert result[0].region == AWS_REGION_US_EAST_1

                assert result[1].status == "FAIL"
                assert (
                    result[1].status_extended
                    == f"User {user} has not used access key 2 in the last 45 days (100 days)."
                )
                assert result[1].resource_id == user + "/AccessKey2"
                assert result[1].resource_arn == arn
                assert result[1].region == AWS_REGION

    @mock_aws
    def test_user_both_access_keys_used(self):
        credentials_last_rotated = (
            datetime.datetime.now() - datetime.timedelta(days=10)
        ).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], audit_config={"max_unused_access_keys_days": 45}
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_user_accesskey_unused.iam_user_accesskey_unused.iam_client",
                new=IAM(aws_provider),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_user_accesskey_unused.iam_user_accesskey_unused import (
                    iam_user_accesskey_unused,
                )

                service_client.credential_report[0]["access_key_1_active"] = "true"
                service_client.credential_report[0][
                    "access_key_1_last_used_date"
                ] = credentials_last_rotated

                service_client.credential_report[0]["access_key_2_active"] = "true"
                service_client.credential_report[0][
                    "access_key_2_last_used_date"
                ] = credentials_last_rotated

                check = iam_user_accesskey_unused()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"User {user} does not have unused access keys for 45 days."
                )
                assert result[0].resource_id == user
                assert result[0].resource_arn == arn
                assert result[0].region == AWS_REGION_US_EAST_1
