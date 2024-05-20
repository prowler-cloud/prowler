from unittest import mock

import botocore
from boto3 import client
from mock import patch
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

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
class Test_apigatewayv2_api_access_logging_enabled:
    @mock_aws
    def test_apigateway_no_apis(self):
        from prowler.providers.aws.services.apigatewayv2.apigatewayv2_service import (
            ApiGatewayV2,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.apigatewayv2.apigatewayv2_api_access_logging_enabled.apigatewayv2_api_access_logging_enabled.apigatewayv2_client",
            new=ApiGatewayV2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.apigatewayv2.apigatewayv2_api_access_logging_enabled.apigatewayv2_api_access_logging_enabled import (
                apigatewayv2_api_access_logging_enabled,
            )

            check = apigatewayv2_api_access_logging_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_apigateway_one_api_with_logging_in_stage(self):
        # Create ApiGatewayV2 Mocked Resources
        apigatewayv2_client = client("apigatewayv2", region_name=AWS_REGION_US_EAST_1)
        # Create ApiGatewayV2 API
        api = apigatewayv2_client.create_api(Name="test-api", ProtocolType="HTTP")
        api_id = api["ApiId"]
        # Get stages mock with stage with logging
        from prowler.providers.aws.services.apigatewayv2.apigatewayv2_service import (
            ApiGatewayV2,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.apigatewayv2.apigatewayv2_api_access_logging_enabled.apigatewayv2_api_access_logging_enabled.apigatewayv2_client",
            new=ApiGatewayV2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.apigatewayv2.apigatewayv2_api_access_logging_enabled.apigatewayv2_api_access_logging_enabled import (
                apigatewayv2_api_access_logging_enabled,
            )

            check = apigatewayv2_api_access_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"API Gateway V2 test-api ID {api_id} in stage test-stage has access logging enabled."
            )

            assert result[0].resource_id == "test-api-test-stage"
            assert (
                result[0].resource_arn
                == f"arn:aws:apigateway:{AWS_REGION_US_EAST_1}::apis/{api_id}"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{}]
