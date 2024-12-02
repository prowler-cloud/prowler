from unittest import mock

import botocore
from moto import mock_aws

from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

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
        codeartifact_client = mock.MagicMock()
        package_name = "test-package"
        package_namespace = "test-namespace"
        repository_arn = f"arn:aws:codebuild:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:repository/test-repository"

        # Setup mock data
        codeartifact_client.repositories = {
            "test-repository": {
                "name": "test-repository",
                "arn": repository_arn,
                "domain_name": "",
                "domain_owner": "",
                "region": AWS_REGION_EU_WEST_1,
                "packages": [
                    {
                        "name": package_name,
                        "namespace": package_namespace,
                        "format": "pypi",
                        "origin_configuration": {
                            "restrictions": {
                                "publish": "ALLOW",
                                "upstream": "ALLOW",
                            }
                        },
                        "latest_version": {
                            "version": "latest",
                            "status": "Published",
                            "origin": {"origin_type": "INTERNAL"},
                        },
                    }
                ],
            }
        }

        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_codeartifact,
        ), mock.patch(
            "prowler.providers.aws.services.codeartifact.codeartifact_client.codeartifact_client",
            new=codeartifact_client,
        ):
            # Test Fixer
            from prowler.providers.aws.services.codeartifact.codeartifact_packages_external_public_publishing_disabled.codeartifact_packages_external_public_publishing_disabled_fixer import (
                fixer,
            )

            assert fixer(package_name, AWS_REGION_EU_WEST_1)

    @mock_aws
    def test_repository_package_public_publishing_origin_internal_error(self):
        codeartifact_client = mock.MagicMock()
        package_name = "test-package"
        package_namespace = "test-namespace"
        repository_arn = f"arn:aws:codebuild:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:repository/test-repository"

        # Setup mock data
        codeartifact_client.repositories = {
            "test-repository": {
                "name": "test-repository",
                "arn": repository_arn,
                "domain_name": "",
                "domain_owner": "",
                "region": AWS_REGION_EU_WEST_1,
                "packages": [
                    {
                        "name": package_name,
                        "namespace": package_namespace,
                        "format": "pypi",
                        "origin_configuration": {
                            "restrictions": {
                                "publish": "ALLOW",
                                "upstream": "ALLOW",
                            }
                        },
                        "latest_version": {
                            "version": "latest",
                            "status": "Published",
                            "origin": {"origin_type": "INTERNAL"},
                        },
                    }
                ],
            }
        }

        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_codeartifact_error,
        ), mock.patch(
            "prowler.providers.aws.services.codeartifact.codeartifact_client.codeartifact_client",
            new=codeartifact_client,
        ):
            # Test Fixer
            from prowler.providers.aws.services.codeartifact.codeartifact_packages_external_public_publishing_disabled.codeartifact_packages_external_public_publishing_disabled_fixer import (
                fixer,
            )

            assert not fixer("package_name_non_existing", AWS_REGION_EU_WEST_1)
