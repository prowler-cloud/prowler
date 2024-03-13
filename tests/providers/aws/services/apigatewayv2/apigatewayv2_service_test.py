import botocore
from boto3 import client
from mock import patch
from moto import mock_aws

from prowler.providers.aws.services.apigatewayv2.apigatewayv2_service import (
    ApiGatewayV2,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

# Mocking ApiGatewayV2 Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    """
    We have to mock every AWS API call using Boto3

    Rationale -> https://github.com/boto/botocore/blob/develop/botocore/client.py#L810:L816
    """
    if operation_name == "GetAuthorizers":
        return {"Items": [{"AuthorizerId": "authorizer-id", "Name": "test-authorizer"}]}
    elif operation_name == "GetStages":
        return {
            "Items": [
                {
                    "AccessLogSettings": {
                        "DestinationArn": "string",
                        "Format": "string",
                    },
                    "StageName": "test-stage",
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_ApiGatewayV2_Service:
    # Test ApiGatewayV2 Service
    @mock_aws
    def test_service(self):
        # ApiGatewayV2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        apigatewayv2 = ApiGatewayV2(aws_provider)
        assert apigatewayv2.service == "apigatewayv2"

    # Test ApiGatewayV2 Client
    @mock_aws
    def test_client(self):
        # ApiGatewayV2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        apigatewayv2 = ApiGatewayV2(aws_provider)
        for regional_client in apigatewayv2.regional_clients.values():
            assert regional_client.__class__.__name__ == "ApiGatewayV2"

    # Test ApiGatewayV2 Session
    @mock_aws
    def test__get_session__(self):
        # ApiGatewayV2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        apigatewayv2 = ApiGatewayV2(aws_provider)
        assert apigatewayv2.session.__class__.__name__ == "Session"

    # Test ApiGatewayV2 Session
    @mock_aws
    def test_audited_account(self):
        # ApiGatewayV2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        apigatewayv2 = ApiGatewayV2(aws_provider)
        assert apigatewayv2.audited_account == AWS_ACCOUNT_NUMBER

    # Test ApiGatewayV2 Get APIs
    @mock_aws
    def test__get_apis__(self):
        # Generate ApiGatewayV2 Client
        apigatewayv2_client = client("apigatewayv2", region_name=AWS_REGION_US_EAST_1)
        # Create ApiGatewayV2 API
        apigatewayv2_client.create_api(
            Name="test-api", ProtocolType="HTTP", Tags={"test": "test"}
        )
        # ApiGatewayV2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        apigatewayv2 = ApiGatewayV2(aws_provider)
        assert len(apigatewayv2.apis) == len(apigatewayv2_client.get_apis()["Items"])
        assert apigatewayv2.apis[0].tags == [{"test": "test"}]

    # Test ApiGatewayV2 Get Authorizers
    @mock_aws
    def test__get_authorizers__(self):
        # Generate ApiGatewayV2 Client
        apigatewayv2_client = client("apigatewayv2", region_name=AWS_REGION_US_EAST_1)
        # Create ApiGatewayV2 Rest API
        api = apigatewayv2_client.create_api(Name="test-api", ProtocolType="HTTP")
        # Create authorizer
        apigatewayv2_client.create_authorizer(
            ApiId=api["ApiId"],
            AuthorizerType="REQUEST",
            IdentitySource=[],
            Name="auth1",
            AuthorizerPayloadFormatVersion="2.0",
        )
        # ApiGatewayV2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        apigatewayv2 = ApiGatewayV2(aws_provider)
        assert apigatewayv2.apis[0].authorizer is True

    # Test ApiGatewayV2 Get Stages
    @mock_aws
    def test__get_stages__(self):
        # Generate ApiGatewayV2 Client
        apigatewayv2_client = client("apigatewayv2", region_name=AWS_REGION_US_EAST_1)
        # Create ApiGatewayV2 Rest API and a deployment stage
        apigatewayv2_client.create_api(Name="test-api", ProtocolType="HTTP")

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        apigatewayv2 = ApiGatewayV2(aws_provider)
        assert apigatewayv2.apis[0].stages[0].logging is True
