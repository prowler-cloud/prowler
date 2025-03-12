from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.appsync.appsync_service import AppSync
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

orig = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListGraphqlApis":
        return {
            "graphqlApis": [
                {
                    "name": "test-merged-api",
                    "apiId": "api_id",
                    "apiType": "MERGED",
                    "arn": f"arn:aws:appsync:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:graphqlapi/test-merged-api",
                    "authenticationType": "API_KEY",
                    "region": AWS_REGION_US_EAST_1,
                    "tags": {"test": "test", "test2": "test2"},
                },
            ]
        }
    return orig(self, operation_name, kwarg)


def mock_make_api_call_v2(self, operation_name, kwarg):
    if operation_name == "ListGraphqlApis":
        return {
            "graphqlApis": [
                {
                    "name": "test-graphql-no-api-key",
                    "apiId": "api_id",
                    "apiType": "GRAPHQL",
                    "arn": f"arn:aws:appsync:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:graphqlapi/test-graphql-no-api-key",
                    "authenticationType": "AWS_IAM",
                    "region": AWS_REGION_US_EAST_1,
                    "tags": {"test": "test", "test2": "test2"},
                },
            ]
        }
    return orig(self, operation_name, kwarg)


def mock_make_api_call_v3(self, operation_name, kwarg):
    if operation_name == "ListGraphqlApis":
        return {
            "graphqlApis": [
                {
                    "name": "test-graphql-api-key",
                    "apiId": "api_id",
                    "apiType": "GRAPHQL",
                    "arn": f"arn:aws:appsync:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:graphqlapi/test-graphql-api-key",
                    "authenticationType": "API_KEY",
                    "region": AWS_REGION_US_EAST_1,
                    "tags": {"test": "test", "test2": "test2"},
                },
            ]
        }
    return orig(self, operation_name, kwarg)


class Test_appsync_graphql_api_no_api_key_authentication:
    @mock_aws
    def test_no_apis(self):
        client("appsync", region_name=AWS_REGION_US_EAST_1)

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_graphql_api_no_api_key_authentication.appsync_graphql_api_no_api_key_authentication.appsync_client",
            new=AppSync(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.appsync.appsync_graphql_api_no_api_key_authentication.appsync_graphql_api_no_api_key_authentication import (
                appsync_graphql_api_no_api_key_authentication,
            )

            check = appsync_graphql_api_no_api_key_authentication()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_merged_api(self):

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_graphql_api_no_api_key_authentication.appsync_graphql_api_no_api_key_authentication.appsync_client",
            new=AppSync(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.appsync.appsync_graphql_api_no_api_key_authentication.appsync_graphql_api_no_api_key_authentication import (
                appsync_graphql_api_no_api_key_authentication,
            )

            check = appsync_graphql_api_no_api_key_authentication()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v2)
    def test_graphql_no_api_key(self):

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_graphql_api_no_api_key_authentication.appsync_graphql_api_no_api_key_authentication.appsync_client",
            new=AppSync(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.appsync.appsync_graphql_api_no_api_key_authentication.appsync_graphql_api_no_api_key_authentication import (
                appsync_graphql_api_no_api_key_authentication,
            )

            check = appsync_graphql_api_no_api_key_authentication()
            result = check.execute()

            assert len(result) == 1
            assert (
                result[0].resource_arn
                == f"arn:aws:appsync:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:graphqlapi/test-graphql-no-api-key"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "api_id"
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "AppSync GraphQL API test-graphql-no-api-key is not using an API KEY for authentication."
            )
            assert result[0].resource_tags == [{"test": "test", "test2": "test2"}]

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v3)
    def test_graphql_api_key(self):

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_graphql_api_no_api_key_authentication.appsync_graphql_api_no_api_key_authentication.appsync_client",
            new=AppSync(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.appsync.appsync_graphql_api_no_api_key_authentication.appsync_graphql_api_no_api_key_authentication import (
                appsync_graphql_api_no_api_key_authentication,
            )

            check = appsync_graphql_api_no_api_key_authentication()
            result = check.execute()

            assert len(result) == 1
            assert (
                result[0].resource_arn
                == f"arn:aws:appsync:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:graphqlapi/test-graphql-api-key"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "api_id"
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "AppSync GraphQL API test-graphql-api-key is using an API KEY for authentication."
            )
            assert result[0].resource_tags == [{"test": "test", "test2": "test2"}]
