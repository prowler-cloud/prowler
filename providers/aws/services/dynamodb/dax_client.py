from providers.aws.lib.audit_info.audit_info import current_audit_info
from providers.aws.services.dynamodb.dynamodb_service import DAX

dax_client = DAX(current_audit_info)
