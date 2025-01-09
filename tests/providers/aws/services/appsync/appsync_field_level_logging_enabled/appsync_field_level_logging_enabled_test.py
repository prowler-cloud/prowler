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
                    "name": "test-log-level",
                    "apiId": "idididid",
                    "apiType": "MERGED",
                    "arn": f"arn:aws:appsync:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:graphqlapi/test-log-level",
                    "authenticationType": "API_KEY",
                    "logConfig": {"fieldLogLevel": "ALL"},
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
                    "name": "test-none-log-level",
                    "apiId": "idididid",
                    "apiType": "GRAPHQL",
                    "arn": f"arn:aws:appsync:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:graphqlapi/test-none-log-level",
                    "authenticationType": "AWS_IAM",
                    "logConfig": {"fieldLogLevel": "NONE"},
                    "region": AWS_REGION_US_EAST_1,
                    "tags": {"test": "test", "test2": "test2"},
                },
            ]
        }
    return orig(self, operation_name, kwarg)


class Test_appsync_field_level_logging_enabled:
    @mock_aws
    def test_no_apis(self):
        client("appsync", region_name=AWS_REGION_US_EAST_1)

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_field_level_logging_enabled.appsync_field_level_logging_enabled.appsync_client",
            new=AppSync(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.appsync.appsync_field_level_logging_enabled.appsync_field_level_logging_enabled import (
                appsync_field_level_logging_enabled,
            )

            check = appsync_field_level_logging_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_graphql_no_api_key(self):

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_field_level_logging_enabled.appsync_field_level_logging_enabled.appsync_client",
            new=AppSync(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.appsync.appsync_field_level_logging_enabled.appsync_field_level_logging_enabled import (
                appsync_field_level_logging_enabled,
            )

            check = appsync_field_level_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert (
                result[0].resource_arn
                == f"arn:aws:appsync:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:graphqlapi/test-log-level"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "idididid"
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "AppSync API test-log-level has field log level enabled."
            )
            assert result[0].resource_tags == [{"test": "test", "test2": "test2"}]

    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v2)
    def test_graphql_api_key(self):

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_field_level_logging_enabled.appsync_field_level_logging_enabled.appsync_client",
            new=AppSync(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.appsync.appsync_field_level_logging_enabled.appsync_field_level_logging_enabled import (
                appsync_field_level_logging_enabled,
            )

            check = appsync_field_level_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert (
                result[0].resource_arn
                == f"arn:aws:appsync:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:graphqlapi/test-none-log-level"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "idididid"
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "AppSync API test-none-log-level does not have field log level enabled."
            )
            assert result[0].resource_tags == [{"test": "test", "test2": "test2"}]
