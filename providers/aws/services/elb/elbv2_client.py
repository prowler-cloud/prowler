from providers.aws.lib.audit_info.audit_info import current_audit_info
from providers.aws.services.elb.elb_service import ELBv2

elbv2_client = ELBv2(current_audit_info)
