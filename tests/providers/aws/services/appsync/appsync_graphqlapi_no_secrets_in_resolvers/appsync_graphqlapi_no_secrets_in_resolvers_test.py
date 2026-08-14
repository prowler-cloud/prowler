from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.appsync.appsync_service import (
    AppSync,
    DataSource,
    GraphqlApi,
    Resolver,
)
from prowler.providers.aws.services.awslambda.awslambda_service import Function
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

orig = botocore.client.BaseClient._make_api_call

APPSYNC_API_NAME = "test-api"
APPSYNC_API_ID = "testapi123456"
APPSYNC_API_ARN = f"arn:aws:appsync:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:apis/{APPSYNC_API_ID}"

# Resolver mapping template with a hardcoded secret
REQUEST_MAPPING_TEMPLATE_WITH_SECRET = """
{
    "version": "2018-05-29",
    "operation": "GetItem",
    "key": {
        "id": $util.dynamodb.toDynamoDBJson($ctx.args.id)
    }
}
#set($db_password = "Tr0ub4dor3xKq9vLmZ")
$util.qr($ctx.stash.put("db_password", $db_password))
"""

RESPONSE_MAPPING_TEMPLATE_WITHOUT_SECRET = """
#if($ctx.error)
    $util.error($ctx.error.message, $ctx.error.type)
#else
    $util.toJson($ctx.result)
#end
"""

# Data source config without secrets
DATA_SOURCE_CONFIG_NO_SECRET = """
{
    "description": "Test data source for DynamoDB",
    "tableName": "test-table"
}
"""


def create_graphql_api_no_resources():
    return GraphqlApi(
        id=APPSYNC_API_ID,
        name=APPSYNC_API_NAME,
        arn=APPSYNC_API_ARN,
        region=AWS_REGION_US_EAST_1,
        type="GRAPHQL",
        field_log_level="ALL",
        authentication_type="AWS_IAM",
        resolvers=[],
        data_sources=[],
        tags=[{}],
    )


def create_graphql_api_with_resolver_secret():
    api = GraphqlApi(
        id=APPSYNC_API_ID,
        name=APPSYNC_API_NAME,
        arn=APPSYNC_API_ARN,
        region=AWS_REGION_US_EAST_1,
        type="GRAPHQL",
        field_log_level="ALL",
        authentication_type="AWS_IAM",
        resolvers=[
            Resolver(
                arn=f"{APPSYNC_API_ARN}/types/Query/fields/getUser",
                type_name="Query",
                field_name="getUser",
                data_source_name="TestDataSource",
                kind="UNIT",
                request_mapping_template=REQUEST_MAPPING_TEMPLATE_WITH_SECRET,
                response_mapping_template=RESPONSE_MAPPING_TEMPLATE_WITHOUT_SECRET,
                pipeline_functions=[],
                region=AWS_REGION_US_EAST_1,
            )
        ],
        data_sources=[],
        tags=[{}],
    )
    return api


def create_graphql_api_without_secrets():
    api = GraphqlApi(
        id=APPSYNC_API_ID,
        name=APPSYNC_API_NAME,
        arn=APPSYNC_API_ARN,
        region=AWS_REGION_US_EAST_1,
        type="GRAPHQL",
        field_log_level="ALL",
        authentication_type="AWS_IAM",
        resolvers=[
            Resolver(
                arn=f"{APPSYNC_API_ARN}/types/Query/fields/getUser",
                type_name="Query",
                field_name="getUser",
                data_source_name="TestDataSource",
                kind="UNIT",
                request_mapping_template=RESPONSE_MAPPING_TEMPLATE_WITHOUT_SECRET,
                response_mapping_template=RESPONSE_MAPPING_TEMPLATE_WITHOUT_SECRET,
                pipeline_functions=[],
                region=AWS_REGION_US_EAST_1,
            )
        ],
        data_sources=[
            DataSource(
                arn=f"arn:aws:appsync:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:apis/{APPSYNC_API_ID}/datasources/TestDataSource",
                name="TestDataSource",
                type="AMAZON_DYNAMODB",
                description="Test data source",
                lambda_config={},
                dynamodb_config={
                    "tableName": "test-table",
                    "awsRegion": AWS_REGION_US_EAST_1,
                    "useCallerCredentials": True,
                },
                elasticsearch_config={},
                http_config={},
                relational_database_config={},
                region=AWS_REGION_US_EAST_1,
            )
        ],
        tags=[{}],
    )
    return api


class Test_appsync_graphqlapi_no_secrets_in_resolvers:
    @mock_aws
    def test_no_apis(self):
        client("appsync", region_name=AWS_REGION_US_EAST_1)

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.appsync.appsync_graphqlapi_no_secrets_in_resolvers.appsync_graphqlapi_no_secrets_in_resolvers.appsync_client",
                new=AppSync(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.appsync.appsync_graphqlapi_no_secrets_in_resolvers.appsync_graphqlapi_no_secrets_in_resolvers import (
                appsync_graphqlapi_no_secrets_in_resolvers,
            )

            check = appsync_graphqlapi_no_secrets_in_resolvers()
            result = check.execute()

            assert len(result) == 0

    def test_api_no_resources(self):
        appsync_client = mock.MagicMock
        appsync_client.graphql_apis = {
            APPSYNC_API_ARN: create_graphql_api_no_resources()
        }
        appsync_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.appsync.appsync_graphqlapi_no_secrets_in_resolvers.appsync_graphqlapi_no_secrets_in_resolvers.appsync_client",
                new=appsync_client,
            ),
        ):
            from prowler.providers.aws.services.appsync.appsync_graphqlapi_no_secrets_in_resolvers.appsync_graphqlapi_no_secrets_in_resolvers import (
                appsync_graphqlapi_no_secrets_in_resolvers,
            )

            check = appsync_graphqlapi_no_secrets_in_resolvers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == APPSYNC_API_NAME
            assert result[0].resource_arn == APPSYNC_API_ARN
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in AppSync GraphQL API {APPSYNC_API_NAME} resolver mapping templates or data sources."
            )
            assert result[0].resource_tags == [{}]

    def test_api_resolver_with_secret(self):
        appsync_client = mock.MagicMock
        appsync_client.graphql_apis = {
            APPSYNC_API_ARN: create_graphql_api_with_resolver_secret()
        }
        appsync_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.appsync.appsync_graphqlapi_no_secrets_in_resolvers.appsync_graphqlapi_no_secrets_in_resolvers.appsync_client",
                new=appsync_client,
            ),
        ):
            from prowler.providers.aws.services.appsync.appsync_graphqlapi_no_secrets_in_resolvers.appsync_graphqlapi_no_secrets_in_resolvers import (
                appsync_graphqlapi_no_secrets_in_resolvers,
            )

            check = appsync_graphqlapi_no_secrets_in_resolvers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == APPSYNC_API_NAME
            assert result[0].resource_arn == APPSYNC_API_ARN
            assert result[0].status == "FAIL"
            assert "resolver" in result[0].status_extended
            assert "Query.getUser.requestMappingTemplate" in result[0].status_extended

    def test_api_without_secrets(self):
        appsync_client = mock.MagicMock
        appsync_client.graphql_apis = {
            APPSYNC_API_ARN: create_graphql_api_without_secrets()
        }
        appsync_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.appsync.appsync_graphqlapi_no_secrets_in_resolvers.appsync_graphqlapi_no_secrets_in_resolvers.appsync_client",
                new=appsync_client,
            ),
        ):
            from prowler.providers.aws.services.appsync.appsync_graphqlapi_no_secrets_in_resolvers.appsync_graphqlapi_no_secrets_in_resolvers import (
                appsync_graphqlapi_no_secrets_in_resolvers,
            )

            check = appsync_graphqlapi_no_secrets_in_resolvers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == APPSYNC_API_NAME
            assert result[0].resource_arn == APPSYNC_API_ARN
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in AppSync GraphQL API {APPSYNC_API_NAME} resolver mapping templates or data sources."
            )

    def test_scan_failure_reports_manual(self):
        from prowler.lib.utils.utils import SecretsScanError

        appsync_client = mock.MagicMock
        appsync_client.graphql_apis = {
            APPSYNC_API_ARN: create_graphql_api_with_resolver_secret()
        }
        appsync_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.appsync.appsync_graphqlapi_no_secrets_in_resolvers.appsync_graphqlapi_no_secrets_in_resolvers.appsync_client",
                new=appsync_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.appsync.appsync_graphqlapi_no_secrets_in_resolvers.appsync_graphqlapi_no_secrets_in_resolvers.detect_secrets_scan_batch",
                side_effect=SecretsScanError("Kingfisher exited with code 1"),
            ),
        ):
            from prowler.providers.aws.services.appsync.appsync_graphqlapi_no_secrets_in_resolvers.appsync_graphqlapi_no_secrets_in_resolvers import (
                appsync_graphqlapi_no_secrets_in_resolvers,
            )

            check = appsync_graphqlapi_no_secrets_in_resolvers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Could not scan" in result[0].status_extended
