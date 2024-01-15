from prowler.providers.aws.services.apigatewayv2.apigatewayv2_service import (
    ApiGatewayV2,
)
from prowler.providers.common.common import get_global_provider

apigatewayv2_client = ApiGatewayV2(get_global_provider())
