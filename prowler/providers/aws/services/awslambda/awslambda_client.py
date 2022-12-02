from providers.aws.lib.audit_info.audit_info import current_audit_info
from providers.aws.services.awslambda.awslambda_service import Lambda

awslambda_client = Lambda(current_audit_info)
