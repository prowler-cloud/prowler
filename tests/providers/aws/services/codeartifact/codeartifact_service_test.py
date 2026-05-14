from unittest.mock import patch

import botocore

from prowler.providers.aws.services.codeartifact.codeartifact_service import (
    CodeArtifact,
    LatestPackageVersionStatus,
    OriginInformationValues,
    RestrictionValues,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call

TEST_REPOSITORY_ARN = f"arn:aws:codebuild:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:repository/test-repository"


def mock_make_api_call(self, operation_name, kwarg):
    """We have to mock every AWS API call using Boto3"""
    if operation_name == "ListRepositories":
        return {
            "repositories": [
                {
                    "name": "test-repository",
                    "administratorAccount": AWS_ACCOUNT_NUMBER,
                    "domainName": "test-domain",
                    "domainOwner": AWS_ACCOUNT_NUMBER,
                    "arn": TEST_REPOSITORY_ARN,
                    "description": "test description",
                },
            ]
        }
    if operation_name == "ListPackages":
        return {
            "packages": [
                {
                    "format": "pypi",
                    "namespace": "test-namespace",
                    "package": "test-package",
                    "originConfiguration": {
                        "restrictions": {
                            "publish": "ALLOW",
                            "upstream": "ALLOW",
                        }
                    },
                },
            ],
        }

    if operation_name == "ListPackageVersions":
        assert (
            kwarg.get("maxResults") == 1
        ), "list_package_versions must pass maxResults=1 to avoid fetching all versions"
        return {
            "defaultDisplayVersion": "latest",
            "format": "pypi",
            "namespace": "test-namespace",
            "package": "test-package",
            "versions": [
                {
                    "version": "latest",
                    "revision": "lates",
                    "status": "Published",
                    "origin": {
                        "domainEntryPoint": {
                            "repositoryName": "test-repository",
                            "externalConnectionName": "",
                        },
                        "originType": "INTERNAL",
                    },
                },
            ],
        }

    if operation_name == "ListTagsForResource":
        return {
            "tags": [
                {"key": "test", "value": "test"},
            ]
        }

    return make_api_call(self, operation_name, kwarg)


# Mock generate_regional_clients()
def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_CodeArtifact_Service:
    # Test CodeArtifact Client
    def test_get_client(self):
        codeartifact = CodeArtifact(
            set_mocked_aws_provider([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
        )
        assert (
            codeartifact.regional_clients[AWS_REGION_EU_WEST_1].__class__.__name__
            == "CodeArtifact"
        )

    # Test CodeArtifact Session
    def test__get_session__(self):
        codeartifact = CodeArtifact(
            set_mocked_aws_provider([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
        )
        assert codeartifact.session.__class__.__name__ == "Session"

    # Test CodeArtifact Service
    def test__get_service__(self):
        codeartifact = CodeArtifact(
            set_mocked_aws_provider([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
        )
        assert codeartifact.service == "codeartifact"

    def test_list_repositories(self):
        # Set partition for the service
        codeartifact = CodeArtifact(
            set_mocked_aws_provider([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
        )

        assert len(codeartifact.repositories) == 1
        assert codeartifact.repositories
        assert codeartifact.repositories[
            f"arn:aws:codebuild:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:repository/test-repository"
        ]
        assert codeartifact.repositories[TEST_REPOSITORY_ARN].name == "test-repository"
        assert codeartifact.repositories[
            f"arn:aws:codebuild:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:repository/test-repository"
        ].tags == [
            {"key": "test", "value": "test"},
        ]
        assert codeartifact.repositories[TEST_REPOSITORY_ARN].arn == TEST_REPOSITORY_ARN
        assert (
            codeartifact.repositories[TEST_REPOSITORY_ARN].domain_name == "test-domain"
        )
        assert (
            codeartifact.repositories[TEST_REPOSITORY_ARN].domain_owner
            == AWS_ACCOUNT_NUMBER
        )
        assert (
            codeartifact.repositories[TEST_REPOSITORY_ARN].region
            == AWS_REGION_EU_WEST_1
        )

        assert codeartifact.repositories[
            f"arn:aws:codebuild:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:repository/test-repository"
        ].packages
        assert len(codeartifact.repositories[TEST_REPOSITORY_ARN].packages) == 1
        assert (
            codeartifact.repositories[TEST_REPOSITORY_ARN].packages[0].name
            == "test-package"
        )
        assert (
            codeartifact.repositories[TEST_REPOSITORY_ARN].packages[0].namespace
            == "test-namespace"
        )

        assert (
            codeartifact.repositories[TEST_REPOSITORY_ARN].packages[0].format == "pypi"
        )
        assert (
            codeartifact.repositories[TEST_REPOSITORY_ARN]
            .packages[0]
            .origin_configuration.restrictions.publish
            == RestrictionValues.ALLOW
        )
        assert (
            codeartifact.repositories[TEST_REPOSITORY_ARN]
            .packages[0]
            .origin_configuration.restrictions.upstream
            == RestrictionValues.ALLOW
        )

        assert (
            codeartifact.repositories[TEST_REPOSITORY_ARN]
            .packages[0]
            .latest_version.version
            == "latest"
        )

        assert (
            codeartifact.repositories[TEST_REPOSITORY_ARN]
            .packages[0]
            .latest_version.status
            == LatestPackageVersionStatus.Published
        )

        assert (
            codeartifact.repositories[TEST_REPOSITORY_ARN]
            .packages[0]
            .latest_version.origin.origin_type
            == OriginInformationValues.INTERNAL
        )


def mock_make_api_call_no_namespace(self, operation_name, kwarg):
    """Mock for packages without a namespace to exercise the else branch"""
    if operation_name == "ListRepositories":
        return {
            "repositories": [
                {
                    "name": "test-repository",
                    "administratorAccount": AWS_ACCOUNT_NUMBER,
                    "domainName": "test-domain",
                    "domainOwner": AWS_ACCOUNT_NUMBER,
                    "arn": TEST_REPOSITORY_ARN,
                    "description": "test description",
                },
            ]
        }
    if operation_name == "ListPackages":
        return {
            "packages": [
                {
                    "format": "pypi",
                    "package": "test-package-no-ns",
                    "originConfiguration": {
                        "restrictions": {
                            "publish": "ALLOW",
                            "upstream": "BLOCK",
                        }
                    },
                },
            ],
        }

    if operation_name == "ListPackageVersions":
        assert (
            kwarg.get("maxResults") == 1
        ), "list_package_versions must pass maxResults=1 to avoid fetching all versions"
        assert (
            "namespace" not in kwarg
        ), "namespace should not be passed when package has no namespace"
        return {
            "defaultDisplayVersion": "1.0.0",
            "format": "pypi",
            "package": "test-package-no-ns",
            "versions": [
                {
                    "version": "1.0.0",
                    "revision": "abc123",
                    "status": "Published",
                    "origin": {
                        "domainEntryPoint": {
                            "repositoryName": "test-repository",
                            "externalConnectionName": "",
                        },
                        "originType": "EXTERNAL",
                    },
                },
            ],
        }

    if operation_name == "ListTagsForResource":
        return {"tags": []}

    return make_api_call(self, operation_name, kwarg)


@patch(
    "botocore.client.BaseClient._make_api_call",
    new=mock_make_api_call_no_namespace,
)
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_CodeArtifact_Service_No_Namespace:
    def test_list_packages_no_namespace(self):
        codeartifact = CodeArtifact(
            set_mocked_aws_provider([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
        )

        assert len(codeartifact.repositories[TEST_REPOSITORY_ARN].packages) == 1

        package = codeartifact.repositories[TEST_REPOSITORY_ARN].packages[0]
        assert package.name == "test-package-no-ns"
        assert package.namespace is None
        assert package.format == "pypi"
        assert (
            package.origin_configuration.restrictions.publish == RestrictionValues.ALLOW
        )
        assert (
            package.origin_configuration.restrictions.upstream
            == RestrictionValues.BLOCK
        )
        assert package.latest_version.version == "1.0.0"
        assert package.latest_version.status == LatestPackageVersionStatus.Published
        assert (
            package.latest_version.origin.origin_type
            == OriginInformationValues.EXTERNAL
        )
