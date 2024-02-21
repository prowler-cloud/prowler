from prowler.providers.aws.services.apigateway.apigateway_service import APIGateway
from prowler.providers.common.common import get_global_provider

apigateway_client = APIGateway(get_global_provider())
