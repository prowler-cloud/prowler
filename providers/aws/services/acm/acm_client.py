from providers.aws.lib.audit_info.audit_info import current_audit_info
from providers.aws.services.acm.acm_service import ACM

acm_client = ACM(current_audit_info)
