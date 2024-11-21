from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_ARN,
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

# Original botocore _make_api_call function
orig = botocore.client.BaseClient._make_api_call


# Mocked botocore _make_api_call function
def mock_make_api_call_enabled(self, operation_name, kwarg):
    if operation_name == "ListOrganizationsFeatures":
        return {
            "OrganizationId": "o-test",
            "EnabledFeatures": ["RootSessions", "RootCredentialsManagement"],
        }
    # If we don't want to patch the API call
    return orig(self, operation_name, kwarg)


def mock_make_api_call_disabled(self, operation_name, kwarg):
    if operation_name == "ListOrganizationsFeatures":
        return {"OrganizationId": "o-test", "EnabledFeatures": []}
    # If we don't want to patch the API call
    return orig(self, operation_name, kwarg)


class Test_iam_root_credentials_management_enabled_test:
    @mock_aws
    def test_no_organization(self):
        from prowler.providers.aws.services.iam.iam_service import IAM
        from prowler.providers.aws.services.organizations.organizations_service import (
            Organizations,
        )

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], create_default_organization=False
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_root_credentials_management_enabled.iam_root_credentials_management_enabled.iam_client",
                new=IAM(aws_provider),
            ), mock.patch(
                "prowler.providers.aws.services.iam.iam_root_credentials_management_enabled.iam_root_credentials_management_enabled.organizations_client",
                new=Organizations(aws_provider),
            ):
                from prowler.providers.aws.services.iam.iam_root_credentials_management_enabled.iam_root_credentials_management_enabled import (
                    iam_root_credentials_management_enabled,
                )

                check = iam_root_credentials_management_enabled()
                result = check.execute()

                assert len(result) == 0

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_enabled
    )
    @mock_aws
    def test__root_credentials_management_enabled(self):
        # Create Organization
        conn = client("organizations")
        conn.create_organization()
        from prowler.providers.aws.services.iam.iam_service import IAM
        from prowler.providers.aws.services.organizations.organizations_service import (
            Organizations,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_root_credentials_management_enabled.iam_root_credentials_management_enabled.iam_client",
                new=IAM(aws_provider),
            ), mock.patch(
                "prowler.providers.aws.services.iam.iam_root_credentials_management_enabled.iam_root_credentials_management_enabled.organizations_client",
                new=Organizations(aws_provider),
            ):
                from prowler.providers.aws.services.iam.iam_root_credentials_management_enabled.iam_root_credentials_management_enabled import (
                    iam_root_credentials_management_enabled,
                )

                check = iam_root_credentials_management_enabled()
                result = check.execute()

                assert len(result) == 1

                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "Root credentials management is enabled."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert result[0].resource_arn == AWS_ACCOUNT_ARN
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_disabled
    )
    @mock_aws
    def test__root_credentials_management_disabled(self):
        # Create Organization
        conn = client("organizations")
        conn.create_organization()
        from prowler.providers.aws.services.iam.iam_service import IAM
        from prowler.providers.aws.services.organizations.organizations_service import (
            Organizations,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_root_credentials_management_enabled.iam_root_credentials_management_enabled.iam_client",
                new=IAM(aws_provider),
            ), mock.patch(
                "prowler.providers.aws.services.iam.iam_root_credentials_management_enabled.iam_root_credentials_management_enabled.organizations_client",
                new=Organizations(aws_provider),
            ):
                from prowler.providers.aws.services.iam.iam_root_credentials_management_enabled.iam_root_credentials_management_enabled import (
                    iam_root_credentials_management_enabled,
                )

                check = iam_root_credentials_management_enabled()
                result = check.execute()

                assert len(result) == 1

                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Root credentials management is not enabled."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert result[0].resource_arn == AWS_ACCOUNT_ARN
                assert result[0].region == AWS_REGION_US_EAST_1
