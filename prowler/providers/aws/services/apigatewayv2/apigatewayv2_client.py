from prowler.providers.aws.services.apigatewayv2.apigatewayv2_service import (
    ApiGatewayV2,
)
from prowler.providers.common.provider import Provider

apigatewayv2_client = ApiGatewayV2(Provider.get_global_provider())
