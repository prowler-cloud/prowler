from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

elbv2_client = ELBv2(current_audit_info)
