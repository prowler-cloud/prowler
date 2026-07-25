from unittest import mock

from prowler.lib.utils.utils import SecretsScanError
from prowler.providers.aws.services.appsync.appsync_service import (
    DataSource,
    GraphqlApi,
    Resolver,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

API_ID = "test-api-id"
API_NAME = "test-graphql-api"
API_ARN = f"arn:aws:appsync:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:apis/{API_ID}"

RESOLVER_REQUEST_TEMPLATE_WITH_SECRET = """
{
    "version": "2017-02-28",
    "operation": "Query",
    "query": {
        "expression": "id = :id",
        "expressionValues": {
            ":id": $util.dynamodb.toDynamoDBJson($ctx.args.id)
        }
    },
    "authToken": "hardcoded-api-key-12345"
}
"""

RESOLVER_REQUEST_TEMPLATE_WITHOUT_SECRET = """
{
    "version": "2017-02-28",
    "operation": "Query",
    "query": {
        "expression": "id = :id",
        "expressionValues": {
            ":id": $util.dynamodb.toDynamoDBJson($ctx.args.id)
        }
    }
}
"""

RESOLVER_RESPONSE_TEMPLATE_WITH_SECRET = """
#set($secret = "AKIAIOSFODNN7EXAMPLE")
$util.toJson($ctx.result)
"""

RESOLVER_RESPONSE_TEMPLATE_WITHOUT_SECRET = """
$util.toJson($ctx.result)
"""


def create_graphql_api(
    resolvers=None, data_sources=None, api_name=API_NAME, api_id=API_ID
):
    return GraphqlApi(
        id=api_id,
        name=api_name,
        arn=API_ARN,
        region=AWS_REGION_US_EAST_1,
        type="GRAPHQL",
        field_log_level="ERROR",
        authentication_type="API_KEY",
        tags=[],
        resolvers=resolvers or [],
        data_sources=data_sources or [],
    )


def create_resolver(
    type_name="Query",
    field_name="getUser",
    request_template="",
    response_template="",
    data_source_name="",
):
    return Resolver(
        arn=f"{API_ARN}/types/{type_name}/resolvers/{field_name}",
        type_name=type_name,
        field_name=field_name,
        request_mapping_template=request_template,
        response_mapping_template=response_template,
        data_source_name=data_source_name,
    )


def create_data_source(name="TestDataSource", ds_type="NONE", **configs):
    return DataSource(
        arn=f"{API_ARN}/datasources/{name}",
        name=name,
        type=ds_type,
        **configs,
    )


def mock_batch_scan_with_findings(findings_map):
    """
    Create a mock function for detect_secrets_scan_batch that consumes
    the generator and returns specified findings.

    Args:
        findings_map: dict mapping keys to findings lists
    """
    def mock_scan(payloads, **kwargs):
        # Iterate through payloads and return findings for matching keys
        results = {}
        for key, payload in payloads:
            if key in findings_map:
                results[key] = findings_map[key]
        return results
    return mock_scan


class Test_appsync_graphql_api_no_secrets_in_resolvers:
    def test_no_apis(self):
        appsync_client = mock.MagicMock()
        appsync_client.graphql_apis = {}
        appsync_client.audit_config = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers.appsync_client",
            new=appsync_client,
            create=True,
        ):
            from prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers import (
                appsync_graphql_api_no_secrets_in_resolvers,
            )

            check = appsync_graphql_api_no_secrets_in_resolvers()
            result = check.execute()

            assert len(result) == 0

    def test_api_no_resolvers_no_data_sources(self):
        appsync_client = mock.MagicMock()
        api = create_graphql_api()
        appsync_client.graphql_apis = {API_ARN: api}
        appsync_client.audit_config = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers.appsync_client",
            new=appsync_client,
            create=True,
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers.detect_secrets_scan_batch",
            side_effect=mock_batch_scan_with_findings({}),
            create=True,
        ):
            from prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers import (
                appsync_graphql_api_no_secrets_in_resolvers,
            )

            check = appsync_graphql_api_no_secrets_in_resolvers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in AppSync GraphQL API {API_NAME} resolvers or data sources."
            )
            assert result[0].resource_id == API_ID
            assert result[0].resource_arn == API_ARN
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_api_with_resolver_no_secrets(self):
        appsync_client = mock.MagicMock()
        resolver = create_resolver(
            request_template=RESOLVER_REQUEST_TEMPLATE_WITHOUT_SECRET,
            response_template=RESOLVER_RESPONSE_TEMPLATE_WITHOUT_SECRET,
        )
        api = create_graphql_api(resolvers=[resolver])
        appsync_client.graphql_apis = {API_ARN: api}
        appsync_client.audit_config = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers.appsync_client",
            new=appsync_client,
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers.detect_secrets_scan_batch",
            side_effect=mock_batch_scan_with_findings({}),
            create=True,
        ):
            from prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers import (
                appsync_graphql_api_no_secrets_in_resolvers,
            )

            check = appsync_graphql_api_no_secrets_in_resolvers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in AppSync GraphQL API {API_NAME} resolvers or data sources."
            )

    def test_api_with_secret_in_resolver_request_template(self):
        appsync_client = mock.MagicMock()
        resolver = create_resolver(
            request_template=RESOLVER_REQUEST_TEMPLATE_WITH_SECRET,
            response_template=RESOLVER_RESPONSE_TEMPLATE_WITHOUT_SECRET,
        )
        api = create_graphql_api(resolvers=[resolver])
        appsync_client.graphql_apis = {API_ARN: api}
        appsync_client.audit_config = {}

        # Mock findings for request template
        findings_map = {
            (0, "resolver", "Query.getUser (request template)"): [
                {
                    "type": "Secret Keyword",
                    "line_number": 9,
                    "hashed_secret": "abc123",
                    "is_verified": False,
                }
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers.appsync_client",
            new=appsync_client,
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers.detect_secrets_scan_batch",
            side_effect=mock_batch_scan_with_findings(findings_map),
        ):
            from prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers import (
                appsync_graphql_api_no_secrets_in_resolvers,
            )

            check = appsync_graphql_api_no_secrets_in_resolvers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Potential secret found" in result[0].status_extended
            assert "Resolver Query.getUser (request template)" in result[0].status_extended

    def test_api_with_secret_in_resolver_response_template(self):
        appsync_client = mock.MagicMock()
        resolver = create_resolver(
            request_template=RESOLVER_REQUEST_TEMPLATE_WITHOUT_SECRET,
            response_template=RESOLVER_RESPONSE_TEMPLATE_WITH_SECRET,
        )
        api = create_graphql_api(resolvers=[resolver])
        appsync_client.graphql_apis = {API_ARN: api}
        appsync_client.audit_config = {}

        findings_map = {
            (0, "resolver", "Query.getUser (response template)"): [
                {
                    "type": "AWS Access Key",
                    "line_number": 2,
                    "hashed_secret": "def456",
                    "is_verified": False,
                }
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers.appsync_client",
            new=appsync_client,
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers.detect_secrets_scan_batch",
            side_effect=mock_batch_scan_with_findings(findings_map),
        ):
            from prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers import (
                appsync_graphql_api_no_secrets_in_resolvers,
            )

            check = appsync_graphql_api_no_secrets_in_resolvers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Potential secret found" in result[0].status_extended
            assert "Resolver Query.getUser (response template)" in result[0].status_extended

    def test_api_with_secret_in_data_source_http_config(self):
        appsync_client = mock.MagicMock()
        data_source = create_data_source(
            name="HTTPDataSource",
            ds_type="HTTP",
            http_config={
                "endpoint": "https://api.example.com",
                "authorizationConfig": {
                    "authorizationType": "AWS_IAM",
                    "apiKey": "secret-api-key-abc123",
                },
            },
        )
        api = create_graphql_api(data_sources=[data_source])
        appsync_client.graphql_apis = {API_ARN: api}
        appsync_client.audit_config = {}

        findings_map = {
            (0, "datasource", "HTTPDataSource (http_config)"): [
                {
                    "type": "Secret Keyword",
                    "line_number": 1,
                    "hashed_secret": "ghi789",
                    "is_verified": False,
                }
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers.appsync_client",
            new=appsync_client,
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers.detect_secrets_scan_batch",
            side_effect=mock_batch_scan_with_findings(findings_map),
        ):
            from prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers import (
                appsync_graphql_api_no_secrets_in_resolvers,
            )

            check = appsync_graphql_api_no_secrets_in_resolvers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Potential secret found" in result[0].status_extended
            assert "DataSource HTTPDataSource (http_config)" in result[0].status_extended

    def test_api_with_multiple_secrets(self):
        appsync_client = mock.MagicMock()
        resolver = create_resolver(
            request_template=RESOLVER_REQUEST_TEMPLATE_WITH_SECRET,
        )
        data_source = create_data_source(
            name="HTTPDataSource",
            ds_type="HTTP",
            http_config={
                "endpoint": "https://api.example.com",
                "authorizationConfig": {"apiKey": "secret-key-xyz789"},
            },
        )
        api = create_graphql_api(resolvers=[resolver], data_sources=[data_source])
        appsync_client.graphql_apis = {API_ARN: api}
        appsync_client.audit_config = {}

        findings_map = {
            (0, "resolver", "Query.getUser (request template)"): [
                {
                    "type": "Secret Keyword",
                    "line_number": 9,
                    "hashed_secret": "abc123",
                    "is_verified": False,
                }
            ],
            (0, "datasource", "HTTPDataSource (http_config)"): [
                {
                    "type": "Secret Keyword",
                    "line_number": 1,
                    "hashed_secret": "xyz789",
                    "is_verified": False,
                }
            ],
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers.appsync_client",
            new=appsync_client,
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers.detect_secrets_scan_batch",
            side_effect=mock_batch_scan_with_findings(findings_map),
        ):
            from prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers import (
                appsync_graphql_api_no_secrets_in_resolvers,
            )

            check = appsync_graphql_api_no_secrets_in_resolvers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Potential secrets found" in result[0].status_extended
            assert "Resolver Query.getUser" in result[0].status_extended
            assert "DataSource HTTPDataSource" in result[0].status_extended

    def test_api_with_scan_error(self):
        appsync_client = mock.MagicMock()
        api = create_graphql_api()
        appsync_client.graphql_apis = {API_ARN: api}
        appsync_client.audit_config = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers.appsync_client",
            new=appsync_client,
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers.detect_secrets_scan_batch",
            side_effect=SecretsScanError("Scanner failed"),
        ):
            from prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers import (
                appsync_graphql_api_no_secrets_in_resolvers,
            )

            check = appsync_graphql_api_no_secrets_in_resolvers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Could not scan" in result[0].status_extended
            assert "manual review is required" in result[0].status_extended

    def test_api_with_verified_secret(self):
        appsync_client = mock.MagicMock()
        resolver = create_resolver(
            request_template=RESOLVER_REQUEST_TEMPLATE_WITH_SECRET,
        )
        api = create_graphql_api(resolvers=[resolver])
        appsync_client.graphql_apis = {API_ARN: api}
        appsync_client.audit_config = {"secrets_validate": True}

        # Mock with a verified secret
        findings_map = {
            (0, "resolver", "Query.getUser (request template)"): [
                {
                    "type": "AWS Access Key",
                    "line_number": 9,
                    "hashed_secret": "abc123",
                    "is_verified": True,  # Verified!
                }
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers.appsync_client",
            new=appsync_client,
        ), mock.patch(
            "prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers.detect_secrets_scan_batch",
            side_effect=mock_batch_scan_with_findings(findings_map),
        ):
            from prowler.providers.aws.services.appsync.appsync_graphql_api_no_secrets_in_resolvers.appsync_graphql_api_no_secrets_in_resolvers import (
                appsync_graphql_api_no_secrets_in_resolvers,
            )

            check = appsync_graphql_api_no_secrets_in_resolvers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            # Severity should be escalated to CRITICAL for verified secrets
            assert result[0].check_metadata.Severity == "critical"
            assert "confirmed to be live" in result[0].status_extended
