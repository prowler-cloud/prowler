from providers.aws.lib.audit_info.audit_info import current_audit_info
from providers.aws.services.apigateway.apigateway_service import ApiGateway

apigateway_client = ApiGateway(current_audit_info)
