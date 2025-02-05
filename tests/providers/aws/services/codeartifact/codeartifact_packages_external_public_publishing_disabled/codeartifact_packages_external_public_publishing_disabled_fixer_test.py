from unittest import mock

import botocore
from moto import mock_aws

from prowler.providers.aws.services.codeartifact.codeartifact_service import (
    CodeArtifact,
)
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

mock_make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call_codeartifact(self, operation_name, kwarg):
    if operation_name == "PutPackageOriginConfiguration":
        return {
            "PackageOriginConfiguration": {
                "Restrictions": {
                    "Publish": "BLOCK",
                    "Upstream": "BLOCK",
                }
            }
        }
    return mock_make_api_call(self, operation_name, kwarg)


def mock_make_api_call_codeartifact_error(self, operation_name, kwarg):
    if operation_name == "PutPackageOriginConfiguration":
        raise botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": "PackageNotFound",
                    "Message": "PackageNotFound",
                }
            },
            operation_name,
        )
    return mock_make_api_call(self, operation_name, kwarg)


class Test_codeartifact_packages_external_public_publishing_disabled_fixer:
    @mock_aws
    def test_repository_package_public_publishing_origin_internal(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_codeartifact,
        ):
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ), mock.patch(
                "prowler.providers.aws.services.codeartifact.codeartifact_client.codeartifact_client",
                new=CodeArtifact(aws_provider),
            ):
                # Test Fixer
                from prowler.providers.aws.services.codeartifact.codeartifact_packages_external_public_publishing_disabled.codeartifact_packages_external_public_publishing_disabled_fixer import (
                    fixer,
                )

                assert fixer("test/test-package", AWS_REGION_EU_WEST_1)

    @mock_aws
    def test_repository_package_public_publishing_origin_internal_error(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_codeartifact_error,
        ):

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ), mock.patch(
                "prowler.providers.aws.services.codeartifact.codeartifact_client.codeartifact_client",
                new=CodeArtifact(aws_provider),
            ):
                # Test Fixer
                from prowler.providers.aws.services.codeartifact.codeartifact_packages_external_public_publishing_disabled.codeartifact_packages_external_public_publishing_disabled_fixer import (
                    fixer,
                )

                assert not fixer("non-existing-package", AWS_REGION_EU_WEST_1)
