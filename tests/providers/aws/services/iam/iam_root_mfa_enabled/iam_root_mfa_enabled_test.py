from re import search
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_iam_root_mfa_enabled_test:
    from tests.providers.aws.utils import (
        AWS_ACCOUNT_ARN,
        AWS_ACCOUNT_NUMBER,
        AWS_REGION_US_EAST_1,
        set_mocked_aws_provider,
    )

    @mock_aws
    def test_root_mfa_not_enabled(self):
        iam_client = client("iam")
        user = "test-user"
        iam_client.create_user(UserName=user)["User"]["Arn"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_root_mfa_enabled.iam_root_mfa_enabled.iam_client",
                new=IAM(aws_provider),
            ) as service_client,
        ):
            from prowler.providers.aws.services.iam.iam_root_mfa_enabled.iam_root_mfa_enabled import (
                iam_root_mfa_enabled,
            )

            service_client.credential_report[0]["user"] = "<root_account>"
            service_client.credential_report[0]["mfa_active"] = "false"
            service_client.credential_report[0]["password_enabled"] = "true"
            service_client.credential_report[0]["access_key_1_active"] = "false"
            service_client.credential_report[0]["access_key_2_active"] = "false"
            service_client.credential_report[0][
                "arn"
            ] = "arn:aws:iam::123456789012:<root_account>:root"

            check = iam_root_mfa_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "MFA is not enabled for root account.", result[0].status_extended
            )
            assert result[0].resource_id == "<root_account>"
            assert result[0].resource_arn == service_client.credential_report[0]["arn"]

    @mock_aws
    def test_root_mfa_enabled(self):
        iam_client = client("iam")
        user = "test-user"
        iam_client.create_user(UserName=user)["User"]["Arn"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_root_mfa_enabled.iam_root_mfa_enabled.iam_client",
                new=IAM(aws_provider),
            ) as service_client,
        ):
            from prowler.providers.aws.services.iam.iam_root_mfa_enabled.iam_root_mfa_enabled import (
                iam_root_mfa_enabled,
            )

            service_client.credential_report[0]["user"] = "<root_account>"
            service_client.credential_report[0]["mfa_active"] = "true"
            service_client.credential_report[0]["password_enabled"] = "true"
            service_client.credential_report[0]["access_key_1_active"] = "false"
            service_client.credential_report[0]["access_key_2_active"] = "false"
            service_client.credential_report[0][
                "arn"
            ] = "arn:aws:iam::123456789012:<root_account>:root"

            check = iam_root_mfa_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search("MFA is enabled for root account.", result[0].status_extended)
            assert result[0].resource_id == "<root_account>"
            assert result[0].resource_arn == service_client.credential_report[0]["arn"]

    @mock_aws
    def test_root_no_credentials(self):
        iam_client = client("iam")
        user = "test-user"
        iam_client.create_user(UserName=user)["User"]["Arn"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_root_mfa_enabled.iam_root_mfa_enabled.iam_client",
                new=IAM(aws_provider),
            ) as service_client,
        ):
            from prowler.providers.aws.services.iam.iam_root_mfa_enabled.iam_root_mfa_enabled import (
                iam_root_mfa_enabled,
            )

            service_client.credential_report[0]["user"] = "<root_account>"
            service_client.credential_report[0]["mfa_active"] = "false"
            service_client.credential_report[0]["password_enabled"] = "false"
            service_client.credential_report[0]["access_key_1_active"] = "false"
            service_client.credential_report[0]["access_key_2_active"] = "false"
            service_client.credential_report[0][
                "arn"
            ] = "arn:aws:iam::123456789012:<root_account>:root"

            check = iam_root_mfa_enabled()
            result = check.execute()
            # Should return no findings since root has no credentials
            assert len(result) == 0

    @mock_aws
    def test_root_mfa_with_organizational_management_enabled(self):
        iam_client = client("iam")
        user = "test-user"
        iam_client.create_user(UserName=user)["User"]["Arn"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_root_mfa_enabled.iam_root_mfa_enabled.iam_client",
                new=IAM(aws_provider),
            ) as service_client,
        ):
            from prowler.providers.aws.services.iam.iam_root_mfa_enabled.iam_root_mfa_enabled import (
                iam_root_mfa_enabled,
            )

            # Set up organizational root management
            service_client.organization_features = ["RootCredentialsManagement"]

            service_client.credential_report[0]["user"] = "<root_account>"
            service_client.credential_report[0]["mfa_active"] = "true"
            service_client.credential_report[0]["password_enabled"] = "true"
            service_client.credential_report[0]["access_key_1_active"] = "true"
            service_client.credential_report[0]["access_key_2_active"] = "false"
            service_client.credential_report[0][
                "arn"
            ] = "arn:aws:iam::123456789012:<root_account>:root"

            check = iam_root_mfa_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "Root account has credentials with MFA enabled. "
                "Consider removing individual root credentials since organizational "
                "root management is active.",
                result[0].status_extended,
            )
            assert result[0].resource_id == "<root_account>"
            assert result[0].resource_arn == service_client.credential_report[0]["arn"]

    @mock_aws
    def test_root_mfa_disabled_with_organizational_management_enabled(self):
        iam_client = client("iam")
        user = "test-user"
        iam_client.create_user(UserName=user)["User"]["Arn"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_root_mfa_enabled.iam_root_mfa_enabled.iam_client",
                new=IAM(aws_provider),
            ) as service_client,
        ):
            from prowler.providers.aws.services.iam.iam_root_mfa_enabled.iam_root_mfa_enabled import (
                iam_root_mfa_enabled,
            )

            # Set up organizational root management
            service_client.organization_features = ["RootCredentialsManagement"]

            service_client.credential_report[0]["user"] = "<root_account>"
            service_client.credential_report[0]["mfa_active"] = "false"
            service_client.credential_report[0]["password_enabled"] = "true"
            service_client.credential_report[0]["access_key_1_active"] = "false"
            service_client.credential_report[0]["access_key_2_active"] = "true"
            service_client.credential_report[0][
                "arn"
            ] = "arn:aws:iam::123456789012:<root_account>:root"

            check = iam_root_mfa_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "Root account has credentials without MFA "
                "despite organizational root management being enabled.",
                result[0].status_extended,
            )
            assert result[0].resource_id == "<root_account>"
            assert result[0].resource_arn == service_client.credential_report[0]["arn"]
