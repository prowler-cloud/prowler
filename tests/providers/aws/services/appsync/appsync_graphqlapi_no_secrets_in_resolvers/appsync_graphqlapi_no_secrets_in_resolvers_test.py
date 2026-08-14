from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.appsync.appsync_service import (
    AppSync,
    DataSource,
    GraphqlApi,
    Resolver,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

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

# Inline secret material hardcoded in a data source configuration
INLINE_DATA_SOURCE_SECRET = "Tr0ub4dor3xKq9vLmZ"


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
                http_config={
                    "authorizationConfig": {
                        "authorizationType": "AWS_IAM",
                        "awsIamConfig": {
                            "signingRegion": AWS_REGION_US_EAST_1,
                            "signingServiceName": "appsync",
                        },
                    }
                },
                relational_database_config={
                    "rdsHttpEndpointConfig": {
                        "awsRegion": AWS_REGION_US_EAST_1,
                        "dbClusterIdentifier": "my-cluster",
                        "database": "mydb",
                        "schema": "public",
                        # Reference to a secret in Secrets Manager, not an
                        # inline secret, so it must not be reported.
                        "awsSecretStoreArn": f"arn:aws:secretsmanager:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:secret:my-secret-AbCdEfGh",
                    }
                },
                region=AWS_REGION_US_EAST_1,
            )
        ],
        tags=[{}],
    )
    return api


def create_graphql_api_with_data_source_secret():
    api = GraphqlApi(
        id=APPSYNC_API_ID,
        name=APPSYNC_API_NAME,
        arn=APPSYNC_API_ARN,
        region=AWS_REGION_US_EAST_1,
        type="GRAPHQL",
        field_log_level="ALL",
        authentication_type="AWS_IAM",
        resolvers=[],
        data_sources=[
            DataSource(
                arn=f"arn:aws:appsync:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:apis/{APPSYNC_API_ID}/datasources/TestHttpDataSource",
                name="TestHttpDataSource",
                type="HTTP",
                description="HTTP data source with a hardcoded API key",
                lambda_config={},
                dynamodb_config={},
                elasticsearch_config={},
                http_config={
                    "endpoint": "https://api.example.com/",
                    "authorizationConfig": {
                        "authorizationType": "API_KEY",
                        "apiKey": INLINE_DATA_SOURCE_SECRET,
                    },
                },
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

    @mock_aws
    def test_api_no_resources(self):
        client("appsync", region_name=AWS_REGION_US_EAST_1)

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        appsync_client = AppSync(aws_provider)
        appsync_client.graphql_apis = {
            APPSYNC_API_ARN: create_graphql_api_no_resources()
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
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

    @mock_aws
    def test_api_resolver_with_secret(self):
        client("appsync", region_name=AWS_REGION_US_EAST_1)

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        appsync_client = AppSync(aws_provider)
        appsync_client.graphql_apis = {
            APPSYNC_API_ARN: create_graphql_api_with_resolver_secret()
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
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

    @mock_aws
    def test_api_without_secrets(self):
        client("appsync", region_name=AWS_REGION_US_EAST_1)

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        appsync_client = AppSync(aws_provider)
        appsync_client.graphql_apis = {
            APPSYNC_API_ARN: create_graphql_api_without_secrets()
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
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

    @mock_aws
    def test_scan_failure_reports_manual(self):
        from prowler.lib.utils.utils import SecretsScanError

        client("appsync", region_name=AWS_REGION_US_EAST_1)

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        appsync_client = AppSync(aws_provider)
        appsync_client.graphql_apis = {
            APPSYNC_API_ARN: create_graphql_api_with_resolver_secret()
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
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

    @mock_aws
    def test_api_data_source_with_secret(self):
        client("appsync", region_name=AWS_REGION_US_EAST_1)

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        appsync_client = AppSync(aws_provider)
        appsync_client.graphql_apis = {
            APPSYNC_API_ARN: create_graphql_api_with_data_source_secret()
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
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
            assert "data_source" in result[0].status_extended
            assert "TestHttpDataSource" in result[0].status_extended
